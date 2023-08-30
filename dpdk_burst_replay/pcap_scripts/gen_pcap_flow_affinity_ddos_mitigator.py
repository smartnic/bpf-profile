import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
import os
from gen_pcap_utils import *

# Generator function to read and yield packets one by one
def read_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet_number, packet in enumerate(pcap_reader, start=0):
            yield packet_number, packet

def modify_mac_ip_one_pkt(curr_pkt, src_mac, dst_mac, dst_ip):
    if not curr_pkt.haslayer(IP):
        return None
    src_ip = curr_pkt.getlayer(IP).src
    proto = curr_pkt.getlayer(IP).proto
    new_pkt = Ether(dst = dst_mac, src = src_mac, type = ETH_P_IP)/ \
              IP(src = src_ip, dst = dst_ip, proto = proto)/ \
              curr_pkt[IP].payload
    return new_pkt

def gen_pcap_flow_affinity_ddos_mitigator(dst_mac, dst_ip, output_path, input_file):
    print("start [gen_pcap_flow_affinity_ddos_mitigator]")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    # input_pkts = rdpcap(input_file)
    src_mac = "10:70:fd:d6:a0:1c"
    new_pkts = []
    output_file = f"{output_path}/xdp_ddos_mitigator_flow_affinity.pcap"
    append_flag = False
    for _, pkt in read_packets(input_file):
        new_pkt = modify_mac_ip_one_pkt(pkt, src_mac, dst_mac, dst_ip)
        if new_pkt:
            new_pkts.append(new_pkt)
        if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
            wrpcap(output_file, new_pkts, append=append_flag)
            # print(f"Written {len(new_pkts)} packets to {output_pcap}")
            new_pkts = []
            append_flag = True
    if new_pkts:
        wrpcap(output_file, new_pkts, append=append_flag)
    print(f"[gen_pcap_flow_affinity_ddos_mitigator] output pcap: {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output file name", required=True)
    parser.add_argument("--dst_mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")
    parser.add_argument("--dst_ip", dest="dst_ip", help="Destination IP address to use in the generated PCAP file ", default="172.16.90.196")
    args = parser.parse_args()
    dst_mac = args.dst_mac
    gen_pcap_flow_affinity_ddos_mitigator(dst_mac, args.dst_ip, args.output_path, args.input_file)
