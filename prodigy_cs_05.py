from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import argparse
import sys

def packet_analyzer(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    print(f"\n{timestamp} - New Packet Captured:")
    print("-" * 50)

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Network Layer | Protocol: IPv{ip_layer.version}")
        print(f"Source IP: {ip_layer.src} | Destination IP: {ip_layer.dst}")
        print(f"TTL: {ip_layer.ttl} | Length: {ip_layer.len} bytes")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print("\nTransport Layer | Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}")
            print(f"Sequence: {tcp_layer.seq} | Acknowledgment: {tcp_layer.ack}")
            print(f"Flags: {tcp_layer.flags}")
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("\nTransport Layer | Protocol: UDP")
            print(f"Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}")
            print(f"Length: {udp_layer.len} bytes")
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print("\nTransport Layer | Protocol: ICMP")
            print(f"Type: {icmp_layer.type} | Code: {icmp_layer.code}")
        
        else:
            print(f"\nTransport Layer | Protocol: {ip_layer.proto}")

    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        print(f"\nPayload Preview: {payload[:50].hex()}")

    print(f"\nComplete Packet Summary:\n{packet.summary()}")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string")
    args = parser.parse_args()

    print("Advanced Packet Analyzer Initiated")
    print("Press Ctrl+C to terminate the program")
    print("=" * 70)

    try:
        sniff(iface=args.interface, prn=packet_analyzer, count=args.count, filter=args.filter, store=0)
    except KeyboardInterrupt:
        print("\nPacket capture terminated by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Packet Analyzer shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()
