# ARP Spoofing detector

from scapy.all import Ether,ARP,srp,sniff,conf
import sys

def get_mac(ip):
    """Returns MAC address of any device connected to the network"""

    #srp => send packet and keep listening for response
    res = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),timeout=3,verbose=False)[0]
    return res[0][1].hwsrc

# Call Back function for every sniffed packet
def process(packet):

    if packet.haslayer(ARP):
        #op = 1 => "who has" ; op = 2 => "is-at"
        if packet[ARP].op == 2:
            try:
                #get the real MAC addr
                real_mac = get_mac(packet[ARP].psrc)
                resp_mac = packet[ARP].hwsrc
                if real_mac != resp_mac:
                    print(f"[ ! ] Your are under attack, REAL MAC : {real_mac.upper()}, FAKE-MAC : {resp_mac.upper()}")
            except IndexError:
                #unable to find the real mac
                pass

if __name__ == "__main__":
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface
    finally:
        # we don't store the packet while the sniffing
        sniff(store=False, prn=process, iface=iface)
