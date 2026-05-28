from scapy.all import *

def packet_info(packet):
    
    if packet.haslayer(IP): #check if the packet contains an IP layer

        print("Source IP:", packet[IP].src) #get IP source
        print("Destination IP:", packet[IP].dst) #get IP destination

        protocol = packet[IP].proto # get protocol number

        if protocol == 6:
             print("Protocol: TCP")

        elif protocol == 17:
             print("Protocol: UDP")

        elif protocol == 1:
            print("Protocol: ICMP")

        if packet.haslayer(Raw): #check if packet contains actual data

            print ("Payload:")
            print(packet[Raw].load)# print raw extracted payload bytes
        print("-" * 40)

sniff(prn=packet_info, count=5) #number of tries before disengaging