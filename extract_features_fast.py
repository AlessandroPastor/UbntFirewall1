from scapy.all import PcapReader, IP, TCP, UDP
import pandas as pd
import sys

def extract_features(pcap_file, label):
    flows = {}
    count = 0

    with PcapReader(pcap_file) as reader:
        for pkt in reader:
            count += 1
            if count % 100000 == 0:
                print(f'  Procesados: {count:,} paquetes, IPs: {len(flows)}', flush=True)

            if IP not in pkt:
                continue

            src = pkt[IP].src
            if src not in flows:
                flows[src] = {
                    'total_pkts': 0, 'tcp_pkts': 0,
                    'udp_pkts': 0, 'other_pkts': 0,
                    'unique_dports': set(), 'syn_count': 0,
                    'pkt_sizes': [], 'label': label
                }

            f = flows[src]
            f['total_pkts'] += 1
            f['pkt_sizes'].append(len(pkt))

            if TCP in pkt:
                f['tcp_pkts'] += 1
                f['unique_dports'].add(pkt[TCP].dport)
                if pkt[TCP].flags == 'S':
                    f['syn_count'] += 1
            elif UDP in pkt:
                f['udp_pkts'] += 1
                f['unique_dports'].add(pkt[UDP].dport)
            else:
                f['other_pkts'] += 1

    print(f'Total paquetes: {count:,} | IPs únicas: {len(flows)}')

    rows = []
    for ip, d in flows.items():
        total    = d['total_pkts']
        tcp      = d['tcp_pkts']
        syn      = d['syn_count']
        udports  = len(d['unique_dports'])
        avg_size = sum(d['pkt_sizes']) / total if total > 0 else 0
        syn_ratio       = syn / tcp if tcp > 0 else 0
        port_scan_score = udports / total if total > 0 else 0
        small_syn_score = (syn_ratio / avg_size * 10000) if avg_size > 0 else 0

        rows.append({
            'src_ip':              ip,
            'total_pkts':          total,
            'tcp_pkts':            tcp,
            'udp_pkts':            d['udp_pkts'],
            'other_pkts':          d['other_pkts'],
            'unique_dports_count': udports,
            'syn_ratio':           round(syn_ratio, 4),
            'avg_pkt_size':        round(avg_size, 2),
            'duration_sec':        0,
            'bytes_per_sec':       0,
            'port_scan_score':     round(port_scan_score, 4),
            'small_syn_score':     round(small_syn_score, 4),
            'potential_flood':     1 if syn_ratio > 0.5 and total > 500 else 0,
            'potential_scan':      1 if udports > 100 else 0,
            'label':               label
        })
    return rows

if __name__ == '__main__':
    pcap_file = sys.argv[1]
    label     = sys.argv[2]
    output    = sys.argv[3]

    print(f'Procesando {pcap_file} como [{label}]...')
    rows = extract_features(pcap_file, label)
    df   = pd.DataFrame(rows)
    df.to_csv(output, index=False)
    print(f'Guardado en {output}: {len(df)} filas')
