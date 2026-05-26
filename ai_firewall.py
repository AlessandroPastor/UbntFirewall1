import subprocess, logging, time, os
import pandas as pd
import joblib

MODEL_PATH  = '/home/pastor/firewall-ia-lab/models/firewall_ai_model.joblib'
SCALER_PATH = '/home/pastor/firewall-ia-lab/models/scaler.joblib'
LOG_PATH    = '/var/log/ai_firewall.log'
INTERFACE   = 'enp0s3'
WINDOW_SEC  = 20

WHITELIST = ['127.0.0.1', '192.168.1.43', '192.168.1.41', '10.0.0.1']

FEATURES = ['total_pkts','tcp_pkts','udp_pkts','other_pkts',
            'unique_dports_count','syn_ratio','avg_pkt_size',
            'duration_sec','bytes_per_sec','port_scan_score',
            'small_syn_score','potential_flood','potential_scan']

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
log = logging.getLogger('ai_firewall')

def block_ip(ip):
    if ip in WHITELIST:
        log.info(f'IP en whitelist, ignorada: {ip}')
        return
    r = subprocess.run(
        ['sudo','nft','add','element','inet','filter',
         'ia_blocklist', f'{{ {ip} }}'],
        capture_output=True, text=True)
    if r.returncode == 0:
        log.warning(f'*** BLOQUEADO: {ip} ***')
    else:
        log.error(f'Error bloqueando {ip}: {r.stderr}')

def extract_window(flows, duration):
    rows = []
    for ip, d in flows.items():
        total    = d['total_pkts']
        tcp      = d['tcp_pkts']
        syn      = d['syn_count']
        udports  = len(d['unique_dports'])
        sizes    = d['pkt_sizes']
        avg_size = sum(sizes) / len(sizes) if sizes else 0
        syn_ratio       = syn / tcp if tcp > 0 else 0
        port_scan_score = udports / total if total > 0 else 0
        small_syn_score = (syn_ratio / avg_size * 10000) if avg_size > 0 else 0
        bps             = total / duration if duration > 0 else 0

        rows.append({
            'src_ip':              ip,
            'total_pkts':          total,
            'tcp_pkts':            tcp,
            'udp_pkts':            d['udp_pkts'],
            'other_pkts':          d['other_pkts'],
            'unique_dports_count': udports,
            'syn_ratio':           round(syn_ratio, 4),
            'avg_pkt_size':        round(avg_size, 2),
            'duration_sec':        round(duration, 2),
            'bytes_per_sec':       round(bps, 2),
            'port_scan_score':     round(port_scan_score, 4),
            'small_syn_score':     round(small_syn_score, 4),
            'potential_flood':     1 if syn_ratio > 0.5 and total > 500 else 0,
            'potential_scan':      1 if udports > 100 else 0,
        })
    return rows

def run():
    log.info('=' * 60)
    log.info('AI Firewall iniciado')
    log.info(f'Interfaz : {INTERFACE}')
    log.info(f'Ventana  : {WINDOW_SEC} segundos')
    log.info(f'Whitelist: {WHITELIST}')
    log.info('=' * 60)

    clf    = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    log.info(f'Modelo cargado: {type(clf).__name__}')

    # Captura con dos procesos separados:
    # 1) tcpdump normal para contar paquetes y puertos
    # 2) tcpdump filtrado SYN para contar flags
    cmd_all = ['sudo', 'tcpdump', '-i', INTERFACE,
               '-l', '-n', '-q', '--immediate-mode']
    cmd_syn = ['sudo', 'tcpdump', '-i', INTERFACE,
               '-l', '-n', '-q', '--immediate-mode',
               'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0']

    proc_all = subprocess.Popen(cmd_all, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
    proc_syn = subprocess.Popen(cmd_syn, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)

    flows        = {}
    syn_counts   = {}
    window_start = time.time()
    pkt_count    = 0

    import threading

    def syn_reader():
        for line in proc_syn.stdout:
            line = line.strip()
            if not line or 'listening' in line:
                continue
            parts = line.split()
            try:
                for i, p in enumerate(parts):
                    if p == 'IP' and i+1 < len(parts):
                        raw = parts[i+1]
                        if raw.count('.') >= 4:
                            ip = '.'.join(raw.split('.')[:4])
                        else:
                            ip = raw.split('.')[0]
                        if ip.startswith('192.168.'):
                            syn_counts[ip] = syn_counts.get(ip, 0) + 1
                        break
            except Exception:
                pass

    t = threading.Thread(target=syn_reader, daemon=True)
    t.start()

    log.info('Capturando trafico en tiempo real...')

    for line in proc_all.stdout:
        line = line.strip()
        if not line or 'listening' in line:
            continue

        pkt_count += 1
        parts = line.split()

        try:
            src_ip  = None
            dst_port = '0'

            for i, p in enumerate(parts):
                if p == 'IP' and i+1 < len(parts):
                    raw = parts[i+1]
                    if raw.count('.') >= 4:
                        src_ip = '.'.join(raw.split('.')[:4])
                    else:
                        src_ip = raw
                if p == '>' and i+1 < len(parts):
                    dst_raw = parts[i+1].rstrip(':')
                    if dst_raw.count('.') >= 4:
                        dst_port = dst_raw.split('.')[-1]
                    elif dst_raw.count(':') >= 1:
                        dst_port = dst_raw.split(':')[-1]

            if not src_ip or not src_ip.startswith('192.168.'):
                continue

            if src_ip not in flows:
                flows[src_ip] = {
                    'total_pkts': 0, 'tcp_pkts': 0,
                    'udp_pkts': 0, 'other_pkts': 0,
                    'unique_dports': set(), 'syn_count': 0,
                    'pkt_sizes': []
                }

            d = flows[src_ip]
            d['total_pkts'] += 1
            d['pkt_sizes'].append(74)

            line_lower = line.lower()
            if 'tcp' in line_lower:
                d['tcp_pkts'] += 1
                try:
                    d['unique_dports'].add(int(dst_port))
                except:
                    d['unique_dports'].add(dst_port)
            elif 'udp' in line_lower:
                d['udp_pkts'] += 1
                try:
                    d['unique_dports'].add(int(dst_port))
                except:
                    d['unique_dports'].add(dst_port)
            else:
                d['other_pkts'] += 1

        except Exception:
            pass

        now = time.time()
        if now - window_start >= WINDOW_SEC:
            duration = now - window_start

            # Actualizar syn_counts desde el hilo SYN
            for ip, sc in syn_counts.items():
                if ip in flows:
                    flows[ip]['syn_count'] = sc

            rows = extract_window(flows, duration)

            if rows:
                df     = pd.DataFrame(rows)
                X      = scaler.transform(df[FEATURES].values)
                preds  = clf.predict(X)
                probas = clf.predict_proba(X)

                log.info(f'--- Ventana {WINDOW_SEC}s | {pkt_count} pkts | {len(rows)} IPs ---')

                for i, row in df.iterrows():
                    ip    = row['src_ip']
                    pred  = preds[i]
                    label = clf.classes_[pred] if hasattr(clf, 'classes_') else ('attack' if pred == 0 else 'normal')
                    conf  = probas[i][pred] * 100

                    log.info(
                        f'{ip} | {label} {conf:.1f}% | '
                        f'pkts={int(row["total_pkts"])} '
                        f'syn={row["syn_ratio"]:.3f} '
                        f'ports={int(row["unique_dports_count"])} '
                        f'flood={int(row["potential_flood"])} '
                        f'scan={int(row["potential_scan"])}'
                    )

                    if label == 'attack' or str(label) == '0':
                        log.warning(
                            f'*** ATAQUE DETECTADO: {ip} | '
                            f'confianza={conf:.1f}% ***')
                        block_ip(ip)

            flows        = {}
            syn_counts   = {}
            window_start = now
            pkt_count    = 0

if __name__ == '__main__':
    run()
