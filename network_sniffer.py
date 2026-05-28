from scapy.all import *

def packet_info(packet):
    
    if packet.haslayer(IP):

        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        protocol = packet[IP].proto

        if protocol == 6:
             print("Protocol: TCP")

        elif protocol == 17:
             print("Protocol: UDP")

        elif protocol == 1:
            print("Protocol: ICMP")

        if packet.haslayer(Raw):

            print ("Payload:")
            print(packet[Raw].load)
        print("-" * 40)

sniff(prn=packet_info, count=5)