from scapy.all import sniff, get_if_list
from scapy.utils import wrpcap

def capture_packets(interface="eth0", packet_count=10):
    print(f"Capturing {packet_count} packets on {interface}...")
    packets = sniff(iface=interface, count=packet_count, filter="ip")
    packets.summary()
    wrpcap("packets.pcap", packets)
    print("[*] Packets saved to packets.pcap")
    return packets

if __name__ == "__main__":
    print("Available interfaces:")
    for iface in get_if_list():
        print(" -", iface)

    interface = input("Enter the exact interface name from above: ")
    capture_packets(interface)
