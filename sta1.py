#!/usr/bin/python
from scapy.all import *

# counter=0

def pkt_callback(pkt):

    #This send the packets to interfaces which are connected to the corresponding APs'. Then from those AP's these packets are sent to the controller 
    #via packet-in. Now controller has the datapath of the AP's and can send add or delete flowmods to the APs

    # m ={"00:00:00:00:00:04":"s1-eth3","00:00:00:00:00:05":"s1-eth4","00:00:00:00:00:06":"s1-eth5"}  

    # global counter

    if (pkt[Dot11].addr1 == "00:00:00:00:00:04" or pkt[Dot11].addr2 == "00:00:00:00:00:04"):
        port= "s1-eth3"
    if (pkt[Dot11].addr1 == "00:00:00:00:00:05" or pkt[Dot11].addr2 == "00:00:00:00:00:05"):
        port= "s1-eth4"
    if (pkt[Dot11].addr1 == "00:00:00:00:00:06" or pkt[Dot11].addr2 == "00:00:00:00:00:06"):
        port= "s1-eth5"

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
        # if (pkt[Dot11].addr2 != "00:00:00:00:00:03" and counter==0):
        #     print('Disconnected! Sender MAC address: ', pkt[Dot11].addr1, ', Port: ', port, ', Destination MAC address: ', pkt[Dot11].addr2)
        #     payload_data = b'Disconnect'
        #     packet = Ether(src=pkt[Dot11].addr1, dst=pkt[Dot11].addr2)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=55000, dport=6653)/Raw(load=payload_data)
        #     counter=1
        #     return
        print('Disconnected! Sender MAC address: ', pkt[Dot11].addr2, ', Port: ', port, ', Destination MAC address: ', pkt[Dot11].addr1)
        payload_data = b'Disconnect'
        packet = Ether(src=pkt[Dot11].addr2, dst=pkt[Dot11].addr1)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=55000, dport=6653)/Raw(load=payload_data)
        # counter=1
        sendp(packet, iface=port, verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1:
        # counter=0
        print('Connected! Sender MAC address: ', pkt[Dot11].addr1, ', Port: ', port, ', Destination MAC address: ', pkt[Dot11].addr2)
        payload_data = b'Connect'
        packet = Ether(src=pkt[Dot11].addr1, dst=pkt[Dot11].addr2)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=55001, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface=port, verbose=0)

sniff(iface="hwsim0", prn=pkt_callback)