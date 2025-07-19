from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n[+] IP Packet: {src} -> {dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"    [TCP] Source Port: {packet[TCP].sport} -> Dest Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    [UDP] Source Port: {packet[UDP].sport} -> Dest Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"    [ICMP] Type: {packet[ICMP].type} Code: {packet[ICMP].code}")

def main():
    print("Starting Network Sniffer...")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
