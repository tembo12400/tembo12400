from scapy.all import sniff, wrpcap, IP, TCP
pkts = []
def analyze(p):
    pkts.append(p); info = f"{p[IP].src}:{p[TCP].sport}->{p[IP].dst}:{p[TCP].dport}" if p.haslayer(TCP) else p.summary()
    print(f"{len(pkts):04d} | {len(p)} bytes | {info}")
    if len(pkts) % 100 == 0: wrpcap("dump.pcap", pkts)
print("Sniffing..."); sniff(prn=analyze, store=False); wrpcap("dump.pcap", pkts)