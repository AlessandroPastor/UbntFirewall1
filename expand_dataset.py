from scapy.all import PcapReader, IP, TCP, UDP
import pandas as pd
from datetime import datetime

def extract_windows(pcap_file, label, window_sec=30):
    rows = []
    window = {}
    window_start = None
    count = 0

    with PcapReader(pcap_file) as reader:
        for pkt in reader:
            count += 1
            if count % 1000000 == 0:
                print(f'  {count:,} paquetes...', flush=True)

            if IP not in pkt:
                continue

            ts = float(pkt.time)
            if window_start is None:
                window_start = ts

            # Nueva ventana cada window_sec segundos
            if ts - window_start >= window_sec:
                # Guardar ventana actual
                for ip, d in window.items():
                    total   = d['total_pkts']
                    tcp     = d['tcp_pkts']
                    syn     = d['syn_count']
                    udports = len(d['unique_dports'])
                    avg_size = sum(d['pkt_sizes']) / total if total > 0 else 0
                    syn_ratio = syn / tcp if tcp > 0 else 0
                    duration  = ts - window_start

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
                        'bytes_per_sec':       round(total / duration if duration > 0 else 0, 2),
                        'port_scan_score':     round(udports / total if total > 0 else 0, 4),
                        'small_syn_score':     round(syn_ratio / avg_size * 10000 if avg_size > 0 else 0, 4),
                        'potential_flood':     1 if syn_ratio > 0.5 and total > 500 else 0,
                        'potential_scan':      1 if udports > 100 else 0,
                        'label':               label
                    })

                window = {}
                window_start = ts

            src = pkt[IP].src
            if src not in window:
                window[src] = {
                    'total_pkts': 0, 'tcp_pkts': 0,
                    'udp_pkts': 0, 'other_pkts': 0,
                    'unique_dports': set(), 'syn_count': 0,
                    'pkt_sizes': []
                }

            d = window[src]
            d['total_pkts'] += 1
            d['pkt_sizes'].append(len(pkt))

            if TCP in pkt:
                d['tcp_pkts'] += 1
                d['unique_dports'].add(pkt[TCP].dport)
                if pkt[TCP].flags == 'S':
                    d['syn_count'] += 1
            elif UDP in pkt:
                d['udp_pkts'] += 1
                d['unique_dports'].add(pkt[UDP].dport)
            else:
                d['other_pkts'] += 1

    print(f'Total filas generadas: {len(rows)}')
    return rows

print('Procesando normal...')
rows_n = extract_windows('data/traffic-normal.pcap', 'normal', window_sec=30)
print('Procesando attack...')
rows_a = extract_windows('data/traffic-attack.pcap', 'attack', window_sec=30)

df = pd.concat([pd.DataFrame(rows_n), pd.DataFrame(rows_a)], ignore_index=True)
df.to_csv('data/dataset.csv', index=False)
print(f'\nDataset final:')
print(f'Total filas: {len(df)}')
print(df['label'].value_counts())
print('\nDiferencias entre clases:')
print(df.groupby('label')[['syn_ratio','unique_dports_count','potential_scan','total_pkts']].mean())
