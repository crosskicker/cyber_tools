from sys import argv
from scapy.all import * 

#scanner tout les port
    #send le packet autant de fois qu'il y a de port

def packetSyn(ip):
    print(f"    cible {ip} has :  ")
    for p in range(0,1024):
        packet = IP(dst=ip) / TCP(dport=p, flags="S") # type: ignore
        # We send and wait for 1 packet response
        res = sr1(packet,verbose=False)
        if res.haslayer("TCP"):
            #print(res["TCP"].flags)
            if res["TCP"].flags == "SA":
                print(f"        port {p} : open")

if __name__ == "__main__":
    packetSyn(argv[1])

