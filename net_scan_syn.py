from scapy.all import *
import argparse
import time

# Perform an ARP scan to discover hosts on the network
def get_addresses(network):
    arp = ARP(pdst=network)  # type: ignore # ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet broadcast packet # type: ignore
    packet = ether/arp  # Stack the layers

    # Send the ARP packet and capture the responses
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

# Perform a SYN scan on a machine's ports
def scan_ports(client_ip, client_mac):
    open_ports = []
    
    # Create TCP SYN packets for all specified ports
    packets = Ether(dst=client_mac) / IP(dst=client_ip) / TCP(dport=range(1, 1024), flags="S")  # SYN flag in TCP # type: ignore

    # PROBLEM of response size, it doesn't store received response packets after 147 => acts as if no response!!! Space issue?
    # SOLUTION => filter directly packets received
    # Send the packets and receive the responses
    responses, _ = srp(packets, filter="tcp[13] == 18", timeout=1, verbose=1)

    # Iterate over received responses
    for sent, received in responses:
        if received.haslayer(TCP) and received[TCP].flags == "SA":  # Check if SYN-ACK was received # type: ignore
            open_ports.append(received[TCP].sport)  # The source port is the one we scanned # type: ignore

    return open_ports

def packetSyn(network):
    clients = get_addresses(network)
    for client in clients:
        print(f"Scanning {client['ip']} ({client['mac']})...")
        open_ports = scan_ports(client['ip'], client['mac'])
        if open_ports:
            print(f"    Open ports: {open_ports}")
        else:
            print(f"    No open ports found on {client['ip']}.")

if __name__ == "__main__":
    try:
        # Argument parser
        parser = argparse.ArgumentParser(description="Simple SYN Scan")
        parser.add_argument("target_net", help="Target network address, e.g., 192.168.1.1/24")
        args = parser.parse_args()

        # Start the scan on the IP range
        packetSyn(args.target_net)
        
    except KeyboardInterrupt:
        print("Scan aborted by user.")
