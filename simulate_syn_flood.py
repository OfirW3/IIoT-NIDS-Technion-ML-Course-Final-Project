#!/usr/bin/env python3

from scapy.all import IP, TCP, send
import random
import time
import sys

# ==========================================
# CONFIGURATION
# ==========================================
# Target your local loopback or a specific safe test machine IP
TARGET_IP = "127.0.0.1" 
TARGET_PORT = 80
PACKET_COUNT = 5000  # Enough to trigger a flow, not enough to cause a real DoS
DELAY = 0.005        # 10ms delay between packets

def simulate_syn_flood(target_ip, port, count, delay):
    print(f"[*] Starting controlled SYN flood simulation against {target_ip}:{port}")
    print(f"[*] Sending {count} packets with a {delay}s delay...")
    
    try:
        for i in range(1, count + 1):
            # Randomize the source port to simulate many different connections
            src_port = random.randint(1024, 65535)
            
            # Craft the packet: IP layer + TCP layer with the 'S' (SYN) flag
            ip_layer = IP(dst=target_ip)
            tcp_layer = TCP(sport=src_port, dport=port, flags="S", seq=random.randint(1000, 9000))
            packet = ip_layer / tcp_layer
            
            # Send the packet silently
            send(packet, verbose=0)
            
            if i % 100 == 0:
                print(f"    -> Sent {i}/{count} packets...")
                
            time.sleep(delay)
            
    except PermissionError:
        print("\n[!] ERROR: Scapy requires root privileges to send raw packets.")
        print("    Try running the script with 'sudo python3 simulate_syn.py'")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Simulation aborted by user.")
        sys.exit(0)
        
    print("[*] Simulation complete. Check your NIDS reports!")

if __name__ == "__main__":
    simulate_syn_flood(TARGET_IP, TARGET_PORT, PACKET_COUNT, DELAY)