from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

def main():
    print("[*] Starting packet capture using Scapy...")

    def packet_callback(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                print(f"[TCP] {ip_src}:{sport} -> {ip_dst}:{dport}")
                
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f"[UDP] {ip_src}:{sport} -> {ip_dst}:{dport}")
                
            else:
                print(f"[IP]  {ip_src} -> {ip_dst} (Protocol: {proto})")

        elif packet.haslayer(ARP):
            print(f"[ARP] {packet[ARP].psrc} ({packet[ARP].hwsrc}) requested {packet[ARP].pdst}")

    bpf_filter = "ip or arp"
    sniff(iface="wlp3s0", filter="ip or arp", prn=packet_callback, store=False)

if __name__ == "__main__":
    main()   