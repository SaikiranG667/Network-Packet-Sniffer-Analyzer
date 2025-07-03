from scapy.all import IP, TCP, UDP
from scapy.all import rdpcap
import csv
from collections import defaultdict

def analyze_packets(packets):
    for pkt in packets:
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            proto = pkt[IP].proto

            print(f"[+] IP Packet: {ip_src} -> {ip_dst} | Protocol: {proto}")

            if TCP in pkt:
                print(f"    TCP Port: {pkt[TCP].sport} -> {pkt[TCP].dport}")
            elif UDP in pkt:
                print(f"    UDP Port: {pkt[UDP].sport} -> {pkt[UDP].dport}")


def detect_port_scans(packets):
    scan_map = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            src_ip = pkt["IP"].src
            dst_port = pkt["TCP"].dport
            scan_map[src_ip].add(dst_port)
    
    for src, ports in scan_map.items():
        if len(ports) > 10:  # You can adjust this threshold
            print(f"[!] Possible Port Scan Detected from {src} on ports: {sorted(ports)}")

def export_to_csv(packets, filename="packet_log.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port"])
        for pkt in packets:
            if pkt.haslayer("IP"):
                proto = "TCP" if pkt.haslayer("TCP") else "UDP" if pkt.haslayer("UDP") else "Other"
                src_port = pkt.sport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else ""
                dst_port = pkt.dport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else ""
                writer.writerow([pkt.time, pkt["IP"].src, pkt["IP"].dst, proto, src_port, dst_port])
    print("[*] Packet data exported to packet_log.csv")
packets = rdpcap('packets.pcap')
detect_port_scans(packets)
analyze_packets(packets)
export_to_csv(packets)