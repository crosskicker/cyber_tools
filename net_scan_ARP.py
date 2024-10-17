# Scan ARP (who has @IP)
from scapy.all import ARP, Ether, srp
import argparse


#create an argumentParser object
parser = argparse.ArgumentParser(description="Simple ARP \"who has\" Scan")
parser.add_argument("target_net", help="Target network adress, ex : 192.168.1.1/24")

# parse arguments from the CLI
args = parser.parse_args() 

#IP range ( 192.168.1.1 - 192.168.1.254 )
target_ip = args.target_net

arp = ARP(pdst=target_ip)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")

#stack the layers
packet = ether/arp

#srp() function sends and receives frame ( layer 2 )
result = srp(packet,timeout=3,verbose=0)[0]

clients = []

for sent,received in result:

    clients.append({'ip':received.psrc, 'mac':received.hwsrc})

print("available device")
print("IP"+" "*18+"MAC")

for client in clients:
    print("{:16}   {}".format(client['ip'],client['mac']))