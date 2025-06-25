from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, get_if_list, conf
from collections import defaultdict
import threading
import time
import sys

# ===== Global variables =====
packet_stats = defaultdict(int)
pcap_filename = "captured_packets.pcap"
captured_packets = []
output_filename = "output.txt"  # Output file

# Force raw socket mode (Layer 3 only)
conf.use_pcap = False
conf.L3socket = conf.L3socket

# Function to write output to the file
def write_output(message):
    with open(output_filename, "a") as f:
        f.write(message + "\n")  # Append the message to the output file

# Custom error handler (to avoid logging errors in the log file)
def handle_error(error_message):
    print(f"Error: {error_message}")
    write_output(f"Error: {error_message}")  # Write errors to output file

# ===== Packet Processor =====
def packet_callback(packet):
    try:
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # TCP
        if protocol == 6 and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_stats['TCP'] += 1
            output_message = f"TCP {src_ip}:{tcp_layer.sport} → {dst_ip}:{tcp_layer.dport}"
            print(output_message)
            write_output(output_message)

        # UDP
        elif protocol == 17 and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_stats['UDP'] += 1
            output_message = f"UDP {src_ip}:{udp_layer.sport} → {dst_ip}:{udp_layer.dport}"
            print(output_message)
            write_output(output_message)

        # ICMP
        elif protocol == 1 and packet.haslayer(ICMP):
            packet_stats['ICMP'] += 1
            output_message = f"ICMP {src_ip} → {dst_ip}"
            print(output_message)
            write_output(output_message)

        # Other protocols
        else:
            packet_stats['Other'] += 1
            output_message = f"Other {src_ip} → {dst_ip} Proto:{protocol}"
            print(output_message)
            write_output(output_message)

        # Save packet
        captured_packets.append(packet)
        wrpcap(pcap_filename, captured_packets, append=True)

    except Exception as e:
        handle_error(f"Packet error: {str(e)[:100]}")

# ===== Sniffer Core =====
def start_sniffing(interface=None, count=100, timeout=60):
    # Get available interfaces
    if_list = get_if_list()
    if not if_list:
        handle_error("No network interfaces available")
        return
    
    # Select interface
    if interface is None:
        interface = if_list[0]
    elif interface not in if_list:
        handle_error(f"Interface {interface} not found")
        return

    print(f"\n[+] Starting Layer 3 capture on {interface}")
    print(f"[+] Count: {count}, Timeout: {timeout}s")
    print("[+] Press Ctrl+C to stop\n")

    # Write output to file
    write_output(f"\n[+] Starting Layer 3 capture on {interface}")
    write_output(f"[+] Count: {count}, Timeout: {timeout}s")
    write_output("[+] Press Ctrl+C to stop\n")

    try:
        sniff(
            prn=packet_callback,
            count=count,
            timeout=timeout,
            iface=interface,
            filter="ip",  # Layer 3 filter
            store=False,
            L3socket=conf.L3socket  # Force Layer 3
        )
    except Exception as e:
        handle_error(f"Sniffer error: {str(e)[:100]}")

# ===== Statistics Thread =====
def stats_monitor():
    while True:
        time.sleep(5)
        stats = "\n  ".join(f"{k}: {v}" for k,v in packet_stats.items())
        output_message = f"\n[Stats]\n  {stats}"
        print(output_message)
        write_output(output_message)

# ===== Main Execution =====
def main():
    # Initialize the output file
    with open(output_filename, "w") as f:
        f.write("Packet Sniffer Output\n\n")

    print("Available Interfaces:")
    for i, iface in enumerate(get_if_list()):
        print(f"  {i+1}. {iface}")
        write_output(f"  {i+1}. {iface}")

    # Start stats thread
    stats_thread = threading.Thread(target=stats_monitor, daemon=True)
    stats_thread.start()

    try:
        start_sniffing(
            interface=None,  # Auto-select
            count=100,
            timeout=60
        )
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        write_output("\n[!] Stopped by user")
    except Exception as e:
        handle_error(f"\n[!] Error: {str(e)[:200]}")
    finally:
        print("\n[+] Capture complete")
        print(f"  - PCAP: {pcap_filename}")
        print(f"  - Output: {output_filename}")
        write_output("\n[+] Capture complete")
        write_output(f"  - PCAP: {pcap_filename}")
        write_output(f"  - Output: {output_filename}")

if __name__ == "__main__":
    # Verify Windows
    if not sys.platform.startswith('win'):
        print("Warning: This optimized version works best on Windows")
        write_output("Warning: This optimized version works best on Windows")
    
    # Run as admin check
    try:
        open("C:\\Windows\\Temp\\admin_test", 'w').close()
    except PermissionError:
        print("Warning: Admin privileges recommended for packet capture")
        write_output("Warning: Admin privileges recommended for packet capture")
    
    main()
