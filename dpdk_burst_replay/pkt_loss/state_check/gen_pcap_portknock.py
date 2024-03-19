from scapy.all import *
from scapy.utils import wrpcap


TCP_ONLY = False
PORT_1 = 100
PORT_2 = 101
PORT_3 = 102

def gen_tcp_pkt(dst_mac, dport, tcp_flags):
    # Set the MAC address
    src_mac = "00:00:00:00:00:01"

    # Set the source and destination IP addresses
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.1"

    # Create a TCP SYN packet
    payload_data = b"X" * 10
    tcp_packet = Ether(src=src_mac, dst=dst_mac) / \
                 IP(src=src_ip, dst=dst_ip) / \
                 TCP(sport=12345, dport=dport, flags=tcp_flags) /\
                 Raw(load=payload_data)
    # # Send the packet
    # sendp(tcp_packet)
    return tcp_packet

def gen_tcp_pcap(dst_mac, output_file):
    dport_list = [PORT_1, PORT_2, PORT_3, PORT_1, PORT_1, PORT_1, PORT_1]
    append_flag = False
    for id, dport in enumerate(dport_list):
        pkt = None
        if id == 0:
            pkt = gen_tcp_pkt(dst_mac, dport, "S")
        elif id == len(dport_list) - 1:
            pkt = gen_tcp_pkt(dst_mac, dport, "F")
        else:
            pkt = gen_tcp_pkt(dst_mac, dport, "")
        wrpcap(output_file, pkt, append=append_flag)
        append_flag = True


if __name__ == '__main__':
    dst_mac = "10:70:fd:d6:93:d4"
    output_file = "4pkts_orig.pcap"
    gen_tcp_pcap(dst_mac, output_file)
