 my_own_nmap.py
import socket hostname = input("enter hostname:")
ip= socket.gethostbyname(hostname)
print(ip)
from scapy.all import *
def  analyzer(pkt):
if pkt.haslayer(TCP):
print("tcp packet .....")
# Betwen softwars and pc
src_ip = pkt[IP].src
dst_ip = pkt[IP].dst
mac_src = pkt.src 
mac_dst = pkt.dst
print("SRC-mac: " + mac_src)
print("DST-mac: " + mac_dst)
print("****************************************************")
print("SRC-ip: " + src_ip)
print("DEST-ip: " + dst_ip)
print("++++++++++SCANING+++++++++++++")
#dest=destination src= la source
if pkt.haslayer(UDP):
print("UDP packet....")
src_ip = pkt[IP].src
dst_ip = pkt[IP].dst
mac_src = pkt.src 
mac_dst = pkt.dst 
print("SRC-mac: " + mac_src)
print("DST-mac: " + mac_dst)
# mac= mac adresss
print("****************************************************")
print("SRC-ip: " + src_ip)
print("DEST-ip: " + dst_ip)
print("++++++++++SCANING+++++++++++++")
# Betwen pc and routers
if pkt.haslayer(ICMP):
print("ICMP PACKET ...")
src_ip = pkt[IP].src
dst_ip = pkt[IP].dst
mac_src = pkt.src
mac_dst = pkt.dst 
print("SRC-mac: " + mac_src)
print("DST-mac: " + mac_dst)
print("****************************************************")
print("SRC-ip: " + src_ip)
print("DEST-ip: " + dst_ip)
# when some one ping u or u ping someone
print("++++++++++SCANING+++++++++++++")
sniff(iface="Wi-Fi",prn=analyzer)
# this is nessessaryy!!!!!
