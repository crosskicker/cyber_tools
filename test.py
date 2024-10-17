from scapy.all import *

MAC_R = "70:fc:8f:4d:68:cd"
MAC_P = "f8:b5:4d:9e:31:67"
# Crée un paquet IP avec l'adresse de destination 8.8.8.8
packet = IP(dst="8.8.8.8")  # type: ignore 
#packet.show()  # Affiche le contenu du paquet

# Segment TCP encapsulé dans paquet IP ( / ) avec un drapeau SYN sur le port 80
tcp_packet = IP(dst="8.8.8.8") / TCP(dport=80, flags="S")  # type: ignore 
#tcp_packet.show()


#### Sniffing
#fonction appelé à chaque sniff
def packet_callback(packet):
    print(packet.summary()) #methode summary (résumé comme visu Wireshark != show (details))

# Capture 10 paquets sur l'interface réseau par défaut
#sniff(count=1, prn=packet_callback)


def packet_callback2(packet):
    if packet.haslayer("Ether"):
        # Accède à la couche Ethernet
        ether_layer = packet["Ether"]
        
        # Vérifie si l'adresse MAC source n'est pas MAC_R ou MAC_P
        if ether_layer.src != MAC_R and ether_layer.src != MAC_P:
            # Vérifie si le paquet contient une couche IP
            if packet.haslayer("IP"):
                ip_layer = packet["IP"]
                print(f"C'est chelou : {ether_layer.src} avec l'IP : {ip_layer.src}")
            else:
                print(f"C'est chelou : {packet.summary()}")
    else:
        print("Pas de couche Ethernet dans ce paquet.")

#capture sur une carte réseau specified
sniff(iface="lo", count=5, prn=lambda x: x.summary())
