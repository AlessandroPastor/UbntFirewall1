from flask import Flask, jsonify, render_template_string, request
import subprocess, os, threading, time
import pandas as pd
from datetime import datetime
from collections import deque

app = Flask(__name__)

BLOCK_HISTORY  = []
TRAFFIC_BUFFER = deque(maxlen=60)
PACKET_STATS   = {'total': 0, 'dropped': 0}
LIVE_FLOWS     = {}
AI_EVENTS      = deque(maxlen=100)
_lock          = threading.Lock()

KNOWN_DEVICES = {
    '192.168.1.1':  {'name': 'Router Movistar',     'icon': 'router',         'role': 'gateway',  'vendor': 'Askey Computer'},
    '192.168.1.43': {'name': 'Ubuntu Firewall',      'icon': 'server',         'role': 'firewall', 'vendor': 'VirtualBox'},
    '192.168.1.41': {'name': 'Windows 10 Admin',     'icon': 'device-desktop', 'role': 'admin',    'vendor': 'Unknown'},
    '192.168.1.50': {'name': 'Kali Linux Atacante',  'icon': 'bug',            'role': 'attacker', 'vendor': 'VirtualBox'},
    '192.168.1.33': {'name': 'Samsung Galaxy',       'icon': 'device-mobile',  'role': 'mobile',   'vendor': 'Samsung'},
    '192.168.1.35': {'name': 'Dispositivo IoT',      'icon': 'wifi',           'role': 'iot',      'vendor': 'Unknown'},
    '192.168.1.38': {'name': 'Dispositivo WiFi',     'icon': 'wifi',           'role': 'unknown',  'vendor': 'Unknown'},
    '192.168.1.40': {'name': 'Dispositivo WiFi',     'icon': 'wifi',           'role': 'unknown',  'vendor': 'Unknown'},
}

ROLE_COLORS = {
    'gateway':  '#2563eb', 'firewall': '#16a34a', 'admin': '#d97706',
    'attacker': '#dc2626', 'mobile':   '#7c3aed', 'iot':   '#0891b2', 'unknown': '#6b7280',
}

PROTO_MAP = {
    '22':'SSH','80':'HTTP','443':'HTTPS','53':'DNS','67':'DHCP',
    '68':'DHCP','123':'NTP','21':'FTP','25':'SMTP','3389':'RDP','8080':'HTTP-ALT',
}

def traffic_monitor():
    cmd = ['tcpdump','-i','enp0s3','-l','-n','-q','--immediate-mode']
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        last_snap = time.time()
        pkt_win = byte_win = 0
        for line in proc.stdout:
            line = line.strip()
            if not line or 'listening' in line:
                continue
            with _lock:
                PACKET_STATS['total'] += 1
                pkt_win  += 1
                byte_win += len(line)
                parts = line.split()
                src_ip, proto, dport = 'unknown', 'TCP', '-'
                try:
                    for i, p in enumerate(parts):
                        if p == 'IP' and i+1 < len(parts):
                            raw = parts[i+1]
                            src_ip = '.'.join(raw.split('.')[:4]) if raw.count('.') >= 4 else raw
                        if p == '>' and i+1 < len(parts):
                            dst = parts[i+1].rstrip(':')
                            dport = dst.split('.')[-1] if '.' in dst else dst
                    if 'udp' in line.lower(): proto = 'UDP'
                    elif 'arp' in line.lower(): proto = 'ARP'; src_ip = 'ARP'
                except: pass
                if src_ip and src_ip != 'unknown' and src_ip.startswith('192.168.1.'):
                    if src_ip not in LIVE_FLOWS:
                        dev = KNOWN_DEVICES.get(src_ip, {})
                        LIVE_FLOWS[src_ip] = {
                            'pkts':0,'bytes':0,'proto':proto,'protos':{},
                            'first_seen':datetime.now().strftime('%H:%M:%S'),
                            'last_seen': datetime.now().strftime('%H:%M:%S'),
                            'name': dev.get('name','Desconocido'),
                            'icon': dev.get('icon','wifi'),
                            'role': dev.get('role','unknown'),
                        }
                    f = LIVE_FLOWS[src_ip]
                    f['pkts']     += 1
                    f['bytes']    += len(line)
                    f['last_seen'] = datetime.now().strftime('%H:%M:%S')
                    f['proto']     = proto
                    f['protos'][proto] = f['protos'].get(proto, 0) + 1
            now = time.time()
            if now - last_snap >= 1.0:
                with _lock:
                    TRAFFIC_BUFFER.append({'ts': datetime.now().strftime('%H:%M:%S'), 'pkts': pkt_win, 'bytes': byte_win})
                pkt_win = byte_win = 0
                last_snap = now
    except Exception as e:
        print(f'traffic_monitor: {e}')

def drop_monitor():
    try:
        proc = subprocess.Popen(['sudo','journalctl','-k','-f','--no-pager'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            if 'NFT-DROP' in line:
                with _lock:
                    PACKET_STATS['dropped'] += 1
    except Exception as e:
        print(f'drop_monitor: {e}')

def ai_log_monitor():
    log_path = '/var/log/ai_firewall.log'
    try:
        proc = subprocess.Popen(['tail','-f',log_path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line: continue
            with _lock:
                level = 'attack' if 'ATAQUE' in line or 'BLOQUEADO' in line else \
                        'warn'   if 'WARNING' in line else 'info'
                AI_EVENTS.appendleft({
                    'ts':    datetime.now().strftime('%H:%M:%S'),
                    'msg':   line,
                    'level': level
                })
    except Exception as e:
        print(f'ai_log_monitor: {e}')

threading.Thread(target=traffic_monitor, daemon=True).start()
threading.Thread(target=drop_monitor,    daemon=True).start()
threading.Thread(target=ai_log_monitor,  daemon=True).start()

def network_scanner_loop():
    global _network_cache, _network_last
    while True:
        try:
            _network_cache = scan_network()
            _network_last  = time.time()
        except: pass
        time.sleep(30)

threading.Thread(target=network_scanner_loop, daemon=True).start()

def get_blocked_ips():
    try:
        r = subprocess.run(['sudo','nft','list','set','inet','filter','ia_blocklist'], capture_output=True, text=True)
        ips = []
        for line in r.stdout.splitlines():
            for p in line.strip().strip('{}').split():
                p = p.strip(',')
                if p.count('.') == 3: ips.append(p)
        return list(set(ips))
    except: return []

def get_nft_logs():
    try:
        r = subprocess.run(['sudo','journalctl','-k','--no-pager','-n','200'], capture_output=True, text=True)
        return [l for l in r.stdout.splitlines() if 'NFT-DROP' in l][-20:]
    except: return []

def get_rules():
    try:
        r = subprocess.run(['sudo','nft','list','ruleset'], capture_output=True, text=True)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except: return []

def get_fw_status():
    try:
        r = subprocess.run(['systemctl','is-active','nftables'], capture_output=True, text=True)
        return r.stdout.strip() == 'active'
    except: return False

def get_ai_status():
    try:
        r = subprocess.run(['systemctl','is-active','ai-firewall'], capture_output=True, text=True)
        return r.stdout.strip() == 'active'
    except: return False

def get_ifaces():
    try:
        r = subprocess.run(['ip','a'], capture_output=True, text=True)
        ifaces, current = [], None
        for line in r.stdout.splitlines():
            if line and line[0].isdigit():
                name = line.split(':')[1].strip()
                current = {'name':name,'ip':'sin IP','up':'UP' in line,'promisc':'PROMISC' in line}
                ifaces.append(current)
            elif 'inet ' in line and current:
                current['ip'] = line.strip().split()[1]
        return ifaces
    except: return []

def get_dataset_info():
    path = os.path.expanduser('~/firewall-ia-lab/data/dataset.csv')
    try:
        df = pd.read_csv(path)
        vc = df['label'].value_counts().to_dict()
        return {'total':len(df),'normal':int(vc.get('normal',0)),'attack':int(vc.get('attack',0))}
    except: return {'total':0,'normal':0,'attack':0}

def get_model_metrics():
    try:
        import joblib
        from sklearn.metrics import roc_auc_score, confusion_matrix, precision_score, recall_score, f1_score, accuracy_score
        from sklearn.preprocessing import LabelEncoder
        from sklearn.model_selection import train_test_split
        base   = os.path.expanduser('~/firewall-ia-lab')
        clf    = joblib.load(f'{base}/models/firewall_ai_model.joblib')
        scaler = joblib.load(f'{base}/models/scaler.joblib')
        df     = pd.read_csv(f'{base}/data/dataset.csv')
        FEATURES = ['total_pkts','tcp_pkts','udp_pkts','other_pkts','unique_dports_count',
                    'syn_ratio','avg_pkt_size','duration_sec','bytes_per_sec',
                    'port_scan_score','small_syn_score','potential_flood','potential_scan']
        X  = df[FEATURES].values
        le = LabelEncoder()
        y  = le.fit_transform(df['label'].values)
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        X_sc   = scaler.transform(X_test)
        y_pred = clf.predict(X_sc)
        y_prob = clf.predict_proba(X_sc)[:,1]
        cm     = confusion_matrix(y_test, y_pred).tolist()
        return {
            'auc':       round(float(roc_auc_score(y_test, y_prob)), 3),
            'recall':    round(float(recall_score(y_test, y_pred, zero_division=0)), 3),
            'precision': round(float(precision_score(y_test, y_pred, zero_division=0)), 3),
            'f1':        round(float(f1_score(y_test, y_pred, zero_division=0)), 3),
            'accuracy':  round(float(accuracy_score(y_test, y_pred)), 3),
            'cm': cm, 'model_type': type(clf).__name__
        }
    except Exception as e: return {'error': str(e)}

_network_cache = []
_network_last  = 0

def scan_network_cached():
    blocked = get_blocked_ips()
    for dev in _network_cache:
        dev['blocked'] = dev['ip'] in blocked
    return _network_cache


def scan_network():
    try:
        r = subprocess.run(['sudo','nmap','-sn','-T4','192.168.1.0/24'], capture_output=True, text=True, timeout=30)
        devices, current = [], {}
        blocked = get_blocked_ips()
        for line in r.stdout.splitlines():
            if 'Nmap scan report for' in line:
                if current: devices.append(current)
                raw = line.replace('Nmap scan report for','').strip()
                ip  = raw.split('(')[-1].strip(')') if '(' in raw else raw
                hn  = raw.split('(')[0].strip()     if '(' in raw else ''
                dev = KNOWN_DEVICES.get(ip, {})
                current = {
                    'ip':ip,'hostname':hn or dev.get('name','-'),
                    'mac':'-','vendor':dev.get('vendor','-'),
                    'name':dev.get('name','Desconocido'),
                    'icon':dev.get('icon','wifi'),
                    'role':dev.get('role','unknown'),
                    'color':ROLE_COLORS.get(dev.get('role','unknown'),'#6b7280'),
                    'blocked': ip in blocked
                }
            elif 'MAC Address:' in line and current:
                parts = line.replace('MAC Address:','').strip().split(' ', 1)
                current['mac'] = parts[0]
                if '-' == current['vendor'] and len(parts) > 1:
                    current['vendor'] = parts[1].strip('()')
        if current: devices.append(current)
        return devices
    except: return []

def get_proto_stats():
    with _lock:
        protos = {}
        for f in LIVE_FLOWS.values():
            for proto, count in f.get('protos', {}).items():
                protos[proto] = protos.get(proto, 0) + count
    return protos

HTML = '''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Firewall IA — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#f8fafc;color:#1e293b;min-height:100vh}
a{color:inherit;text-decoration:none}

header{background:#fff;border-bottom:1px solid #e2e8f0;padding:0 28px;height:60px;
  display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;
  box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.logo{display:flex;align-items:center;gap:12px}
.logo-box{width:36px;height:36px;background:#2563eb;border-radius:8px;
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:18px}
.logo-title{font-size:15px;font-weight:600;color:#1e293b}
.logo-sub{font-size:11px;color:#64748b;margin-top:1px}
.header-right{display:flex;align-items:center;gap:16px}
.badge-live{display:flex;align-items:center;gap:6px;background:#f0fdf4;
  border:1px solid #86efac;border-radius:20px;padding:4px 12px;font-size:11px;
  font-weight:600;color:#16a34a}
.dot-live{width:6px;height:6px;background:#16a34a;border-radius:50%;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.clock{font-size:12px;color:#64748b;font-family:'JetBrains Mono',monospace}

.wrap{padding:20px 28px;max-width:1600px;margin:0 auto}

.sec-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;
  color:#94a3b8;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.sec-label i{font-size:13px}

.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}
.g21{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px}
.g12{display:grid;grid-template-columns:1fr 2fr;gap:16px;margin-bottom:16px}

.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px;
  box-shadow:0 1px 3px rgba(0,0,0,0.04)}

.metric-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px 20px;
  box-shadow:0 1px 3px rgba(0,0,0,0.04);position:relative;overflow:hidden}
.metric-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px}
.mc-red::after{background:#ef4444}.mc-blue::after{background:#2563eb}
.mc-green::after{background:#16a34a}.mc-amber::after{background:#d97706}
.mc-purple::after{background:#7c3aed}.mc-cyan::after{background:#0891b2}
.mc-label{font-size:11px;color:#64748b;margin-bottom:8px;display:flex;align-items:center;gap:6px;font-weight:500}
.mc-label i{font-size:13px}
.mc-val{font-size:28px;font-weight:600;line-height:1}
.mc-sub{font-size:11px;color:#94a3b8;margin-top:5px}
.c-red{color:#ef4444}.c-green{color:#16a34a}.c-blue{color:#2563eb}
.c-amber{color:#d97706}.c-purple{color:#7c3aed}.c-cyan{color:#0891b2}.c-gray{color:#64748b}

table{width:100%;border-collapse:collapse;font-size:12px}
th{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;
   color:#94a3b8;padding:8px 12px;text-align:left;border-bottom:1px solid #f1f5f9}
td{padding:8px 12px;border-bottom:1px solid #f8fafc;color:#374151}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
code{font-family:'JetBrains Mono',monospace;font-size:11px;color:#2563eb;
  background:#eff6ff;padding:1px 5px;border-radius:4px}

.badge{padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;
  display:inline-flex;align-items:center;gap:3px}
.badge i{font-size:11px}
.b-red{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}
.b-green{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0}
.b-blue{background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe}
.b-amber{background:#fffbeb;color:#d97706;border:1px solid #fde68a}
.b-purple{background:#faf5ff;color:#7c3aed;border:1px solid #e9d5ff}
.b-cyan{background:#ecfeff;color:#0891b2;border:1px solid #a5f3fc}
.b-gray{background:#f8fafc;color:#64748b;border:1px solid #e2e8f0}

.dev-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;margin-bottom:16px}
.dev-card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:14px;
  transition:box-shadow 0.2s,border-color 0.2s}
.dev-card:hover{box-shadow:0 4px 12px rgba(0,0,0,0.08);border-color:#cbd5e1}
.dev-card.blocked{border-color:#fca5a5;background:#fef2f2}
.dev-card.attacker{border-color:#f87171}
.dev-hdr{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.dev-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;
  justify-content:center;font-size:15px;flex-shrink:0}
.dev-name{font-size:12px;font-weight:500;color:#1e293b;line-height:1.3}
.dev-ip{font-size:10px;color:#64748b;margin-top:1px;font-family:'JetBrains Mono',monospace}
.dev-footer{display:flex;justify-content:space-between;align-items:center;margin-top:8px}
.dev-traffic{font-size:10px;color:#64748b;display:flex;align-items:center;gap:4px}

.ctrl-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
input[type=text]{background:#f8fafc;border:1px solid #e2e8f0;color:#1e293b;
  padding:8px 12px;border-radius:8px;font-family:'Inter',sans-serif;font-size:13px;
  flex:1;min-width:200px;outline:none;transition:border-color 0.2s}
input[type=text]:focus{border-color:#2563eb;background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,0.1)}
.btn{padding:8px 14px;border-radius:8px;border:none;cursor:pointer;
  font-family:'Inter',sans-serif;font-size:12px;font-weight:600;
  display:inline-flex;align-items:center;gap:6px;transition:all 0.15s}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 8px rgba(0,0,0,0.1)}
.btn i{font-size:13px}
.btn-red{background:#ef4444;color:#fff}
.btn-green{background:#16a34a;color:#fff}
.btn-amber{background:#d97706;color:#fff}
.btn-sm{padding:4px 10px;font-size:10px;transform:none!important;box-shadow:none!important}

.msg{padding:8px 12px;border-radius:8px;font-size:12px;margin-bottom:10px;
  display:none;border:1px solid;font-weight:500}

.metric-bar-row{display:flex;align-items:center;gap:10px;padding:6px 0;
  border-bottom:1px solid #f1f5f9}
.metric-bar-row:last-child{border:none}
.mbar-name{font-size:11px;color:#64748b;flex:1;font-weight:500}
.mbar-track{flex:2;height:6px;background:#f1f5f9;border-radius:3px;overflow:hidden}
.mbar-fill{height:100%;border-radius:3px;transition:width 0.8s}
.mbar-val{font-size:12px;font-weight:600;min-width:44px;text-align:right}
.mbar-thr{font-size:10px;color:#94a3b8;min-width:44px}

.cm-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:12px}
.cm-cell{padding:12px;text-align:center;border-radius:8px;border:1px solid #e2e8f0}
.cm-lbl{font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;font-weight:600}
.cm-num{font-size:22px;font-weight:600;display:block;margin-top:3px}
.cm-tn{background:#eff6ff}.cm-tn .cm-num{color:#2563eb}
.cm-fp{background:#fffbeb}.cm-fp .cm-num{color:#d97706}
.cm-fn{background:#fef2f2}.cm-fn .cm-num{color:#ef4444}
.cm-tp{background:#f0fdf4}.cm-tp .cm-num{color:#16a34a}

.iface-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.iface-card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;
  padding:10px 16px;flex:1;min-width:140px}
.iface-card h4{font-size:12px;font-weight:600;color:#2563eb;margin-bottom:4px;
  display:flex;align-items:center;gap:6px}
.iface-card p{font-size:12px;color:#374151;font-family:'JetBrains Mono',monospace}
.iface-stat{font-size:10px;margin-top:4px;display:flex;gap:6px}

.log-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
  padding:10px 14px;height:200px;overflow-y:auto;font-size:11px;
  color:#64748b;font-family:'JetBrains Mono',monospace;line-height:1.7}
.log-box div{padding:2px 0;border-bottom:1px solid #f1f5f9}
.log-box div:last-child{border:none}
.log-attack{color:#ef4444;font-weight:500}
.log-warn{color:#d97706}
.log-info{color:#374151}

.ai-event{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9;align-items:flex-start}
.ai-event:last-child{border:none}
.ai-event-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px}
.ai-event-time{font-size:10px;color:#94a3b8;font-family:'JetBrains Mono',monospace;min-width:55px}
.ai-event-msg{font-size:11px;color:#374151;flex:1;line-height:1.5}

.flow-bar{height:4px;background:#f1f5f9;border-radius:2px;overflow:hidden;margin-top:3px;width:80px}
.flow-fill{height:100%;border-radius:2px;transition:width 0.5s}

canvas{max-height:200px!important}

.section-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.section-hdr-left{display:flex;align-items:center;gap:8px}
.section-title{font-size:13px;font-weight:600;color:#1e293b}
.section-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;
  justify-content:center;font-size:14px}

.tab-row{display:flex;gap:2px;background:#f1f5f9;border-radius:8px;padding:3px;margin-bottom:14px}
.tab{padding:5px 14px;border-radius:6px;font-size:11px;font-weight:600;color:#64748b;
  cursor:pointer;transition:all 0.15s}
.tab.active{background:#fff;color:#1e293b;box-shadow:0 1px 3px rgba(0,0,0,0.1)}

.status-row{display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:#f8fafc;border-radius:8px;margin-bottom:8px;border:1px solid #f1f5f9}
.status-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;
  justify-content:center;font-size:16px;flex-shrink:0}
.status-name{font-size:12px;font-weight:600;color:#1e293b}
.status-desc{font-size:10px;color:#64748b;margin-top:1px}
.status-badge{margin-left:auto}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-box"><i class="ti ti-shield-lock"></i></div>
    <div>
      <div class="logo-title">Firewall con Inteligencia Artificial</div>
      <div class="logo-sub">Cristian Cabana Sulca &amp; Alessandro Pastor Mamani — Seguridad Informática Ciclo 9 — Juliaca, Puno</div>
    </div>
  </div>
  <div class="header-right">
    <div class="badge-live"><div class="dot-live"></div>EN VIVO</div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</header>

<div class="wrap">

<!-- MÉTRICAS TOP -->
<div style="margin-bottom:6px" class="sec-label"><i class="ti ti-chart-bar"></i>Métricas del sistema</div>
<div class="g4">
  <div class="metric-card mc-red">
    <div class="mc-label"><i class="ti ti-ban" style="color:#ef4444"></i>IPs bloqueadas</div>
    <div class="mc-val c-red" id="m-blocked">0</div>
    <div class="mc-sub">en ia_blocklist nftables</div>
  </div>
  <div class="metric-card mc-cyan">
    <div class="mc-label"><i class="ti ti-activity" style="color:#0891b2"></i>Paquetes/seg</div>
    <div class="mc-val c-cyan" id="m-pkts">0</div>
    <div class="mc-sub">capturados en enp0s3</div>
  </div>
  <div class="metric-card mc-amber">
    <div class="mc-label"><i class="ti ti-flame" style="color:#d97706"></i>Paquetes dropeados</div>
    <div class="mc-val c-amber" id="m-dropped">0</div>
    <div class="mc-sub">NFT-DROP acumulado</div>
  </div>
  <div class="metric-card mc-green">
    <div class="mc-label"><i class="ti ti-shield-check" style="color:#16a34a"></i>Firewall nftables</div>
    <div class="mc-val" id="m-fw">--</div>
    <div class="mc-sub" id="m-fw-sub">verificando...</div>
  </div>
</div>

<div class="g4">
  <div class="metric-card mc-blue">
    <div class="mc-label"><i class="ti ti-database" style="color:#2563eb"></i>Dataset total</div>
    <div class="mc-val c-blue" id="m-total">0</div>
    <div class="mc-sub" id="m-ds-sub">normal: 0 / attack: 0</div>
  </div>
  <div class="metric-card mc-purple">
    <div class="mc-label"><i class="ti ti-brain" style="color:#7c3aed"></i>AUC-ROC modelo</div>
    <div class="mc-val" id="m-auc">--</div>
    <div class="mc-sub">umbral ≥ 0.95</div>
  </div>
  <div class="metric-card mc-green">
    <div class="mc-label"><i class="ti ti-target" style="color:#16a34a"></i>Recall (attack)</div>
    <div class="mc-val" id="m-recall">--</div>
    <div class="mc-sub">umbral ≥ 0.90</div>
  </div>
  <div class="metric-card mc-red">
    <div class="mc-label"><i class="ti ti-robot" style="color:#ef4444"></i>Motor IA</div>
    <div class="mc-val" id="m-ai">--</div>
    <div class="mc-sub" id="m-ai-sub">ai-firewall.service</div>
  </div>
</div>

<!-- INTERFACES -->
<div class="sec-label"><i class="ti ti-network"></i>Interfaces de red — Ubuntu Server Firewall (192.168.1.43)</div>
<div class="iface-row" id="ifaces"></div>

<!-- DISPOSITIVOS EN RED -->
<div class="sec-label"><i class="ti ti-router"></i>Dispositivos conectados — Red Movistar 192.168.1.0/24</div>
<div class="dev-grid" id="dev-grid">
  <div style="color:#94a3b8;font-size:12px;grid-column:1/-1">Escaneando red...</div>
</div>

<!-- GRÁFICAS -->
<div class="g2">
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#e0f2fe"><i class="ti ti-chart-line" style="color:#0891b2"></i></div>
        <div class="section-title">Tráfico en tiempo real — paquetes/seg</div>
      </div>
    </div>
    <div style="position:relative;height:180px">
      <canvas id="chartPkts" role="img" aria-label="Paquetes por segundo en tiempo real">Tráfico de red en tiempo real</canvas>
    </div>
  </div>
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#faf5ff"><i class="ti ti-chart-donut" style="color:#7c3aed"></i></div>
        <div class="section-title">Protocolos detectados en la red</div>
      </div>
    </div>
    <div style="position:relative;height:180px">
      <canvas id="chartProto" role="img" aria-label="Distribución de protocolos">Protocolos de red</canvas>
    </div>
  </div>
</div>

<!-- FLUJOS + MOTOR IA -->
<div class="g21">
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#f0fdf4"><i class="ti ti-activity" style="color:#16a34a"></i></div>
        <div class="section-title">Flujos de red en tiempo real</div>
      </div>
      <span class="badge b-blue" id="flow-count">0 IPs</span>
    </div>
    <table>
      <tr><th>Dispositivo</th><th>IP</th><th>Paquetes</th><th>Bytes</th><th>Proto</th><th>Visto</th><th>Estado</th></tr>
      <tbody id="flows-table"><tr><td colspan="7" style="color:#94a3b8;text-align:center;padding:20px">Capturando tráfico...</td></tr></tbody>
    </table>
  </div>
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#faf5ff"><i class="ti ti-brain" style="color:#7c3aed"></i></div>
        <div class="section-title">Motor de IA — métricas</div>
      </div>
      <span style="font-size:10px;color:#94a3b8" id="m-model-type">--</span>
    </div>
    <div id="metric-rows"></div>
    <div class="cm-grid">
      <div class="cm-cell cm-tn"><div class="cm-lbl">Verdadero Neg.</div><span class="cm-num" id="cm-tn">-</span></div>
      <div class="cm-cell cm-fp"><div class="cm-lbl">Falso Pos.</div><span class="cm-num" id="cm-fp">-</span></div>
      <div class="cm-cell cm-fn"><div class="cm-lbl">Falso Neg.</div><span class="cm-num" id="cm-fn">-</span></div>
      <div class="cm-cell cm-tp"><div class="cm-lbl">Verdadero Pos.</div><span class="cm-num" id="cm-tp">-</span></div>
    </div>
  </div>
</div>

<!-- LOG IA EN TIEMPO REAL -->
<div class="g2">
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#fef2f2"><i class="ti ti-robot" style="color:#ef4444"></i></div>
        <div class="section-title">Motor IA — decisiones en tiempo real</div>
      </div>
      <span class="badge b-red" id="ai-attack-count">0 ataques</span>
    </div>
    <div class="log-box" id="ai-log-box">
      <div style="color:#94a3b8;text-align:center;padding:20px">Esperando decisiones del motor IA...</div>
    </div>
  </div>
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#fff7ed"><i class="ti ti-chart-bar" style="color:#d97706"></i></div>
        <div class="section-title">Gráfica de métricas del modelo</div>
      </div>
    </div>
    <div style="position:relative;height:180px">
      <canvas id="chartModel" role="img" aria-label="Métricas del modelo IA">Métricas RandomForest</canvas>
    </div>
  </div>
</div>

<!-- SERVICIOS DEL SISTEMA -->
<div class="sec-label"><i class="ti ti-server"></i>Servicios del sistema</div>
<div class="g3" style="margin-bottom:16px">
  <div class="card">
    <div class="status-row">
      <div class="status-icon" style="background:#f0fdf4"><i class="ti ti-shield" style="color:#16a34a"></i></div>
      <div><div class="status-name">nftables.service</div><div class="status-desc">Firewall del kernel Linux</div></div>
      <div class="status-badge"><span class="badge" id="svc-nft">--</span></div>
    </div>
    <div class="status-row">
      <div class="status-icon" style="background:#faf5ff"><i class="ti ti-brain" style="color:#7c3aed"></i></div>
      <div><div class="status-name">ai-firewall.service</div><div class="status-desc">Motor IA de detección</div></div>
      <div class="status-badge"><span class="badge" id="svc-ai">--</span></div>
    </div>
  </div>
  <div class="card">
    <div class="section-title" style="margin-bottom:10px">ia_blocklist — IPs bloqueadas</div>
    <table>
      <tr><th>IP</th><th>Estado</th><th>Acción</th></tr>
      <tbody id="blocklist-table"><tr><td colspan="3" style="color:#94a3b8">Sin IPs bloqueadas</td></tr></tbody>
    </table>
  </div>
  <div class="card">
    <div class="section-title" style="margin-bottom:10px">Historial de bloqueos</div>
    <table>
      <tr><th>Hora</th><th>IP</th><th>Acción</th></tr>
      <tbody id="historial-table"><tr><td colspan="3" style="color:#94a3b8">Sin historial</td></tr></tbody>
    </table>
  </div>
</div>

<!-- CONTROL FIREWALL -->
<div class="card" style="margin-bottom:16px">
  <div class="section-hdr">
    <div class="section-hdr-left">
      <div class="section-icon" style="background:#fef2f2"><i class="ti ti-settings-automation" style="color:#ef4444"></i></div>
      <div class="section-title">Control del firewall — bloquear / desbloquear IPs manualmente</div>
    </div>
  </div>
  <div id="msg-ctrl" class="msg"></div>
  <div class="ctrl-row">
    <input type="text" id="ip-input" placeholder="Ingresa IP  ej: 192.168.1.50">
    <button class="btn btn-red"   onclick="bloquearIP()"><i class="ti ti-ban"></i>Bloquear IP</button>
    <button class="btn btn-green" onclick="desbloquearIP()"><i class="ti ti-check"></i>Desbloquear IP</button>
    <button class="btn btn-amber" onclick="vaciarBlocklist()"><i class="ti ti-trash"></i>Vaciar blocklist</button>
  </div>
</div>

<!-- LOGS -->
<div class="g2">
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#f8fafc"><i class="ti ti-terminal" style="color:#374151"></i></div>
        <div class="section-title">Log NFT-DROP — kernel</div>
      </div>
    </div>
    <div class="log-box" id="log-box">
      <div style="color:#94a3b8">Sin entradas NFT-DROP aún...</div>
    </div>
  </div>
  <div class="card">
    <div class="section-hdr">
      <div class="section-hdr-left">
        <div class="section-icon" style="background:#f8fafc"><i class="ti ti-list-check" style="color:#374151"></i></div>
        <div class="section-title">Reglas nftables activas</div>
      </div>
    </div>
    <div class="log-box" id="rules-box"></div>
  </div>
</div>

</div>

<script>
setInterval(()=>{document.getElementById('clock').textContent=new Date().toLocaleString('es-PE')},1000)

const ROLE_COLORS={'gateway':'#2563eb','firewall':'#16a34a','admin':'#d97706','attacker':'#ef4444','mobile':'#7c3aed','iot':'#0891b2','unknown':'#6b7280'}
const ROLE_BADGE={'gateway':'b-blue','firewall':'b-green','admin':'b-amber','attacker':'b-red','mobile':'b-purple','iot':'b-cyan','unknown':'b-gray'}

function fmtBytes(b){if(b<1024)return b+'B';if(b<1048576)return (b/1024).toFixed(1)+'K';return (b/1048576).toFixed(1)+'M'}

const chartPkts = new Chart(document.getElementById('chartPkts').getContext('2d'),{
  type:'line',
  data:{labels:[],datasets:[{label:'Pkts/seg',data:[],borderColor:'#0891b2',
    backgroundColor:'rgba(8,145,178,0.08)',tension:0.4,fill:true,pointRadius:0,borderWidth:2}]},
  options:{animation:false,responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'#94a3b8',font:{size:9}},grid:{color:'#f1f5f9'}},
            y:{ticks:{color:'#94a3b8',font:{size:9}},grid:{color:'#f1f5f9'},beginAtZero:true}}}
})

const chartProto = new Chart(document.getElementById('chartProto').getContext('2d'),{
  type:'doughnut',
  data:{labels:[],datasets:[{data:[],
    backgroundColor:['#2563eb','#16a34a','#d97706','#7c3aed','#ef4444','#0891b2','#ec4899','#6b7280'],
    borderWidth:2,borderColor:'#fff',hoverOffset:4}]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{legend:{position:'right',labels:{color:'#374151',font:{size:10},boxWidth:10,padding:8}}}}
})

const chartModel = new Chart(document.getElementById('chartModel').getContext('2d'),{
  type:'bar',
  data:{labels:['AUC','Recall','Precision','F1','Accuracy'],
    datasets:[
      {label:'Modelo',data:[0,0,0,0,0],
       backgroundColor:['#2563eb','#16a34a','#d97706','#7c3aed','#0891b2'],borderRadius:6},
      {label:'Umbral mínimo',data:[0.95,0.90,0.85,0.88,0.90],
       type:'line',borderColor:'#ef4444',borderWidth:2,pointRadius:0,
       backgroundColor:'transparent',tension:0}
    ]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{legend:{labels:{color:'#374151',font:{size:10},boxWidth:10}}},
    scales:{x:{ticks:{color:'#94a3b8',font:{size:9}},grid:{color:'#f1f5f9'}},
            y:{min:0,max:1,ticks:{color:'#94a3b8',font:{size:9}},grid:{color:'#f1f5f9'}}}}
})

function showMsg(text, color){
  const m=document.getElementById('msg-ctrl')
  m.textContent=text;m.style.display='block'
  const cfg={red:{bg:'#fef2f2',cl:'#dc2626',br:'#fecaca'},green:{bg:'#f0fdf4',cl:'#16a34a',br:'#bbf7d0'},amber:{bg:'#fffbeb',cl:'#d97706',br:'#fde68a'}}
  const c=cfg[color]||cfg.amber
  m.style.background=c.bg;m.style.color=c.cl;m.style.borderColor=c.br
  setTimeout(()=>m.style.display='none',4000)
}

async function apiPost(url,body={}){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
  return r.json()
}

let aiAttackCount = 0

async function fetchData(){
  try{
    const d=await(await fetch('/api/status')).json()

    document.getElementById('m-blocked').textContent=d.blocked
    document.getElementById('m-dropped').textContent=d.stats.dropped
    const lastPkt=d.buffer.length?d.buffer[d.buffer.length-1].pkts:0
    document.getElementById('m-pkts').textContent=lastPkt

    const fw=document.getElementById('m-fw')
    fw.textContent=d.fw_active?'ACTIVO':'CAIDO'
    fw.className='mc-val '+(d.fw_active?'c-green':'c-red')
    document.getElementById('m-fw-sub').textContent=d.fw_active?'policy drop · activo':'SERVICIO DETENIDO'

    const ai=document.getElementById('m-ai')
    ai.textContent=d.ai_active?'ACTIVO':'INACTIVO'
    ai.className='mc-val '+(d.ai_active?'c-green':'c-gray')
    document.getElementById('m-ai-sub').textContent=d.ai_active?'detectando ataques':'servicio detenido'

    document.getElementById('svc-nft').innerHTML=d.fw_active?'<i class="ti ti-check"></i> activo':'<i class="ti ti-x"></i> inactivo'
    document.getElementById('svc-nft').className='badge '+(d.fw_active?'b-green':'b-red')
    document.getElementById('svc-ai').innerHTML=d.ai_active?'<i class="ti ti-check"></i> activo':'<i class="ti ti-x"></i> inactivo'
    document.getElementById('svc-ai').className='badge '+(d.ai_active?'b-green':'b-red')

    document.getElementById('m-total').textContent=d.dataset.total
    document.getElementById('m-ds-sub').textContent=`normal: ${d.dataset.normal} / attack: ${d.dataset.attack}`

    if(d.model&&!d.model.error){
      const m=d.model
      const metrics=[
        {name:'AUC-ROC',val:m.auc,thr:0.95,color:'#7c3aed'},
        {name:'Recall',val:m.recall,thr:0.90,color:'#16a34a'},
        {name:'Precision',val:m.precision,thr:0.85,color:'#d97706'},
        {name:'F1-Score',val:m.f1,thr:0.88,color:'#ec4899'},
        {name:'Accuracy',val:m.accuracy,thr:0.90,color:'#2563eb'},
      ]
      const setM=(id,val,thr)=>{const el=document.getElementById(id);if(el){el.textContent=val.toFixed(3);el.className='mc-val '+(val>=thr?'c-green':'c-red')}}
      setM('m-auc',m.auc,0.95);setM('m-recall',m.recall,0.90)
      document.getElementById('m-model-type').textContent=m.model_type||'RandomForest'
      document.getElementById('metric-rows').innerHTML=metrics.map(mt=>
        `<div class="metric-bar-row">
          <div class="mbar-name">${mt.name}</div>
          <div class="mbar-track"><div class="mbar-fill" style="width:${mt.val*100}%;background:${mt.color}"></div></div>
          <div class="mbar-val" style="color:${mt.val>=mt.thr?'#16a34a':'#ef4444'}">${mt.val.toFixed(3)}</div>
          <div class="mbar-thr">≥${mt.thr}</div>
        </div>`).join('')
      if(m.cm&&m.cm.length===2){
        document.getElementById('cm-tn').textContent=m.cm[0][0]
        document.getElementById('cm-fp').textContent=m.cm[0][1]
        document.getElementById('cm-fn').textContent=m.cm[1][0]
        document.getElementById('cm-tp').textContent=m.cm[1][1]
      }
      chartModel.data.datasets[0].data=[m.auc,m.recall,m.precision,m.f1,m.accuracy]
      chartModel.update()
    }else if(d.model&&d.model.error){
      document.getElementById('metric-rows').innerHTML=`<div style="color:#94a3b8;font-size:11px;padding:8px">Modelo no cargado: ${d.model.error}</div>`
    }

    document.getElementById('ifaces').innerHTML=d.ifaces.map(i=>
      `<div class="iface-card">
        <h4><i class="ti ti-${i.name.startsWith('lo')?'loop':'network'}"></i>${i.name}</h4>
        <p>${i.ip}</p>
        <div class="iface-stat">
          <span style="color:${i.up?'#16a34a':'#ef4444'};font-size:10px;font-weight:600">${i.up?'● UP':'● DOWN'}</span>
          ${i.promisc?'<span class="badge b-cyan" style="font-size:8px">PROMISC</span>':''}
        </div>
      </div>`).join('')

    const buf=d.buffer.slice(-30)
    chartPkts.data.labels=buf.map(p=>p.ts)
    chartPkts.data.datasets[0].data=buf.map(p=>p.pkts)
    chartPkts.update()

    const protos=d.proto_stats
    const protoKeys=Object.keys(protos).sort((a,b)=>protos[b]-protos[a]).slice(0,7)
    chartProto.data.labels=protoKeys
    chartProto.data.datasets[0].data=protoKeys.map(k=>protos[k])
    chartProto.update()

    if(d.network&&d.network.length){
      const blocked=d.blocklist
      document.getElementById('dev-grid').innerHTML=d.network.map(dev=>{
        const isBlocked=blocked.includes(dev.ip)
        const col=ROLE_COLORS[dev.role]||'#6b7280'
        const flows=d.flows[dev.ip]
        return `<div class="dev-card ${isBlocked?'blocked':''} ${dev.role==='attacker'?'attacker':''}">
          <div class="dev-hdr">
            <div class="dev-icon" style="background:${col}18;color:${col}"><i class="ti ti-${dev.icon}"></i></div>
            <div><div class="dev-name">${dev.name}</div><div class="dev-ip">${dev.ip}</div></div>
          </div>
          <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:6px">
            <span class="badge ${ROLE_BADGE[dev.role]||'b-gray'}">${dev.role}</span>
            ${isBlocked?'<span class="badge b-red"><i class="ti ti-ban"></i>BLOQ</span>':''}
          </div>
          <div style="font-size:9px;color:#94a3b8;margin-bottom:4px;font-family:JetBrains Mono">${dev.mac}</div>
          <div class="dev-footer">
            ${flows?`<div class="dev-traffic"><i class="ti ti-activity" style="font-size:11px"></i>${flows.pkts}pkts · ${fmtBytes(flows.bytes)}</div>`:'<div></div>'}
            ${isBlocked
              ?`<button class="btn btn-green btn-sm" onclick="desbloquearIPDirect('${dev.ip}')"><i class="ti ti-check"></i>Desbloquear</button>`
              :dev.ip!=='192.168.1.43'&&dev.ip!=='192.168.1.41'
                ?`<button class="btn btn-red btn-sm" onclick="bloquearIPDirect('${dev.ip}')"><i class="ti ti-ban"></i>Bloquear</button>`
                :`<span style="font-size:9px;color:#94a3b8"><i class="ti ti-lock"></i> protegido</span>`}
          </div>
        </div>`}).join('')
    }

    const flows=d.flows
    const blocked=d.blocklist
    const maxPkts=Math.max(...Object.values(flows).map(f=>f.pkts),1)
    const flowKeys=Object.keys(flows).sort((a,b)=>flows[b].pkts-flows[a].pkts).slice(0,15)
    document.getElementById('flow-count').textContent=`${flowKeys.length} IPs`
    document.getElementById('flows-table').innerHTML=flowKeys.length?
      flowKeys.map(ip=>{
        const f=flows[ip]
        const isBlocked=blocked.includes(ip)
        const col=ROLE_COLORS[f.role]||'#6b7280'
        const pct=Math.round((f.pkts/maxPkts)*100)
        return `<tr>
          <td><div style="display:flex;align-items:center;gap:6px">
            <i class="ti ti-${f.icon}" style="color:${col};font-size:13px"></i>
            <span style="font-size:11px;font-weight:500">${f.name}</span>
          </div></td>
          <td><code>${ip}</code></td>
          <td><div>${f.pkts}</div>
            <div class="flow-bar"><div class="flow-fill" style="width:${pct}%;background:${col}"></div></div></td>
          <td>${fmtBytes(f.bytes)}</td>
          <td><span class="badge b-blue">${f.proto}</span></td>
          <td style="color:#94a3b8;font-size:10px">${f.last_seen}</td>
          <td><span class="badge ${isBlocked?'b-red':'b-green'}">${isBlocked?'BLOQ':'OK'}</span></td>
        </tr>`}).join(''):
      '<tr><td colspan="7" style="color:#94a3b8;text-align:center;padding:16px">Esperando tráfico...</td></tr>'

    if(d.ai_events&&d.ai_events.length){
      const attacks=d.ai_events.filter(e=>e.level==='attack').length
      document.getElementById('ai-attack-count').textContent=`${attacks} ataques`
      const aiBox=document.getElementById('ai-log-box')
      aiBox.innerHTML=d.ai_events.slice(0,50).map(e=>
        `<div class="ai-event">
          <div class="ai-event-dot" style="background:${e.level==='attack'?'#ef4444':e.level==='warn'?'#d97706':'#94a3b8'}"></div>
          <div class="ai-event-time">${e.ts}</div>
          <div class="ai-event-msg ${e.level==='attack'?'log-attack':e.level==='warn'?'log-warn':'log-info'}">${e.msg}</div>
        </div>`).join('')
    }

    document.getElementById('blocklist-table').innerHTML=d.blocklist.length?
      d.blocklist.map(ip=>
        `<tr><td><code>${ip}</code></td>
         <td><span class="badge b-red"><i class="ti ti-ban"></i>BLOQUEADA</span></td>
         <td><button class="btn btn-green btn-sm" onclick="desbloquearIPDirect('${ip}')"><i class="ti ti-check"></i></button></td></tr>`).join(''):
      '<tr><td colspan="3" style="color:#94a3b8">Sin IPs bloqueadas</td></tr>'

    document.getElementById('historial-table').innerHTML=d.historial.length?
      [...d.historial].reverse().slice(0,8).map(h=>
        `<tr>
          <td style="color:#94a3b8;font-size:10px">${h.ts.split(' ')[1]}</td>
          <td><code>${h.ip}</code></td>
          <td><span class="badge ${h.action==='BLOCK'?'b-red':h.action==='UNBLOCK'?'b-green':'b-amber'}">${h.action}</span></td>
        </tr>`).join(''):
      '<tr><td colspan="3" style="color:#94a3b8">Sin historial</td></tr>'

    const logBox=document.getElementById('log-box')
    logBox.innerHTML=d.logs.length?
      d.logs.map(l=>`<div>${l}</div>`).join(''):
      '<div style="color:#94a3b8">Sin entradas NFT-DROP aún...</div>'
    logBox.scrollTop=logBox.scrollHeight

    document.getElementById('rules-box').innerHTML=
      d.rules.map(r=>`<div>${r}</div>`).join('')

  }catch(e){console.error('fetchData:',e)}
}

async function bloquearIP(){
  const ip=document.getElementById('ip-input').value.trim()
  if(!ip)return showMsg('Ingresa una IP válida','amber')
  const d=await apiPost('/api/block',{ip})
  showMsg(d.msg,d.ok?'green':'red');fetchData()
}
async function desbloquearIP(){
  const ip=document.getElementById('ip-input').value.trim()
  if(!ip)return showMsg('Ingresa una IP válida','amber')
  const d=await apiPost('/api/unblock',{ip})
  showMsg(d.msg,d.ok?'green':'red');fetchData()
}
async function bloquearIPDirect(ip){
  const d=await apiPost('/api/block',{ip})
  showMsg(d.msg,d.ok?'green':'red')
  fetchData()
  setTimeout(fetchData, 2000)
  setTimeout(fetchData, 5000)
}
async function desbloquearIPDirect(ip){
  const d=await apiPost('/api/unblock',{ip})
  showMsg(d.msg,d.ok?'green':'red')
  fetchData()
  setTimeout(fetchData, 2000)
  setTimeout(fetchData, 5000)
}
async function vaciarBlocklist(){const d=await apiPost('/api/flush');showMsg(d.msg,d.ok?'green':'red');fetchData()}

fetchData()
setInterval(fetchData,3000)
</script>
</body>
</html>'''

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/api/status')
def status():
    with _lock:
        buf   = list(TRAFFIC_BUFFER)
        stats = dict(PACKET_STATS)
        flows = {ip: dict(d) for ip, d in LIVE_FLOWS.items()}
        for f in flows.values(): f.pop('protos', None)
        ai_events = list(AI_EVENTS)

    return jsonify({
        'blocked':     len(get_blocked_ips()),
        'blocklist':   get_blocked_ips(),
        'stats':       stats,
        'buffer':      buf,
        'flows':       flows,
        'proto_stats': get_proto_stats(),
        'fw_active':   get_fw_status(),
        'ai_active':   get_ai_status(),
        'ifaces':      get_ifaces(),
        'rules':       get_rules(),
        'logs':        get_nft_logs(),
        'model':       get_model_metrics(),
        'dataset':     get_dataset_info(),
        'historial':   BLOCK_HISTORY,
        'network':     scan_network_cached(),
        'ai_events':   ai_events,
    })

WHITELIST = ['127.0.0.1', '192.168.1.43', '192.168.1.41']

@app.route('/api/block', methods=['POST'])
def block():
    ip = request.json.get('ip','').strip()
    if not ip: return jsonify({'ok':False,'msg':'IP inválida'})
    if ip in WHITELIST: return jsonify({'ok':False,'msg':f'IP {ip} protegida'})
    r = subprocess.run(['sudo','nft','add','element','inet','filter','ia_blocklist',f'{{ {ip} }}'], capture_output=True, text=True)
    if r.returncode == 0:
        BLOCK_HISTORY.append({'ts':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'ip':ip,'action':'BLOCK','origin':'Dashboard manual'})
        return jsonify({'ok':True,'msg':f'IP {ip} bloqueada'})
    return jsonify({'ok':False,'msg':f'Error: {r.stderr}'})

@app.route('/api/unblock', methods=['POST'])
def unblock():
    ip = request.json.get('ip','').strip()
    r = subprocess.run(['sudo','nft','delete','element','inet','filter','ia_blocklist',f'{{ {ip} }}'], capture_output=True, text=True)
    if r.returncode == 0:
        BLOCK_HISTORY.append({'ts':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'ip':ip,'action':'UNBLOCK','origin':'Dashboard manual'})
        return jsonify({'ok':True,'msg':f'IP {ip} desbloqueada'})
    return jsonify({'ok':False,'msg':f'Error: {r.stderr}'})

@app.route('/api/flush', methods=['POST'])
def flush():
    r = subprocess.run(['sudo','nft','flush','set','inet','filter','ia_blocklist'], capture_output=True, text=True)
    if r.returncode == 0:
        BLOCK_HISTORY.append({'ts':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'ip':'*','action':'FLUSH','origin':'Dashboard manual'})
        return jsonify({'ok':True,'msg':'Blocklist vaciada'})
    return jsonify({'ok':False,'msg':'Error al vaciar'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
