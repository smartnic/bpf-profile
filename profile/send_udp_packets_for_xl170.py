# sudo python3 send_udp_packets_xl170.py [dport]

from scapy.all import*
import sys

def send_udp_packets(dport):
    packet = Ether(src="9c:dc:71:5d:01:51",dst="9c:dc:71:5d:57:d1")/IP(src="10.10.1.2",dst="10.10.1.1")/UDP(sport=53,dport=dport)/Raw("123456789012")
    packets = 100000 * packet
    sendpfast(packets, iface="ens1f1", pps=1000000, loop=100000000)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please specify the destion port.")
        sys.exit(0)
    
    dport = int(sys.argv[1])
    print("dport = ", dport)
    send_udp_packets(dport=dport)
