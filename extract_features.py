from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import sys
import os

def extract_features(pcap_file, label):
    packets = rdpcap(pcap_file)
    flows = {}


    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        if src not in flows:
            flows[src] = {
                'total_pkts': 0,
                'tcp_pkts': 0,
                'udp_pkts': 0,
                'other_pkts': 0,
                'unique_dports': set(),
                'syn_count': 0,
                'pkt_sizes': [],
                'label': label
            }
        flows[src]['total_pkts'] += 1
        flows[src]['pkt_sizes'].append(len(pkt))
        
        if TCP in pkt:
            flows[src]['tcp_pkts'] += 1
            flows[src]['unique_dports'].add(pkt[TCP].dport)
            if pkt[TCP].flags == 'S':
                flows[src]['syn_count'] += 1
        elif UDP in pkt:
            flows[src]['udp_pkts'] += 1
            flows[src]['unique_dports'].add(pkt[UDP].dport)
        else:
            flows[src]['other_pkts'] += 1

    rows = []
    for ip, d in flows.items():
        total = d['total_pkts']
        tcp = d['tcp_pkts']
        syn = d['syn_count']
        udports = len(d['unique_dports'])
        avg_size = sum(d['pkt_sizes']) / total if total > 0 else 0
        syn_ratio = syn / tcp if tcp > 0 else 0
        port_scan_score = udports / total if total > 0 else 0
        small_syn_score = (syn_ratio / avg_size * 10000) if avg_size > 0 else 0 
        potencial_flood = 1 if syn_ratio > 0.5 and total > 500 else 0
        potencial_scan = 1 if udports > 100 else 0 

        rows.append({
            'src_ip' : ip,
            'total_pkts': total,
            'tcp_pkts': tcp,
            'udp_pkts': d['udp_pkts'],
            'other_pkts': d['other_pkts'],
            'unique_dports_count': udports,
            'syn_ratio': round(syn_ratio, 4),
            'avg_pkt_size': round(avg_size, 2),
            'duration_sec': 0,
            'bytes_per_sec': 0,
            'port_scan_score': round(port_scan_score, 4),
            'small_syn_score': round(small_syn_score, 4),
            'potential_flood': potencial_flood,
            'potential_scan': potencial_scan,
            'label': d['label']
        })
    return rows

if __name__ == '__main__':
    if len(sys.argv) !=3:
        print('Uso: python3 extract_features.py archivo.pcap normal|attack')
        sys.exit(1)
    pcap_file = sys.argv[1]
    label     = sys.argv[2]
    rows      = extract_features(pcap_file, label)
    df        = pd.DataFrame(rows)
    print(df.to_csv(index=False))
