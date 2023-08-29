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
        for packet_number, packet in enumerate(pcap_reader, start=1):
            yield packet_number, packet

def modify_mac_one_pkt(curr_pkt, src_mac, dst_mac):
    new_pkt = Ether(dst = dst_mac, src = src_mac, type=ETH_P_IP)/ \
              curr_pkt[Ether].payload
    return new_pkt

def gen_pcap_flow_affinity_hhd(dst_mac, output_path, input_file):
    print("start [gen_pcap_flow_affinity_hhd]")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    # input_pkts = rdpcap(input_file)
    src_mac = "10:70:fd:d6:a0:1c"
    new_pkts = []
    output_file = f"{output_path}/xdp_hhd_flow_affinity.pcap"
    for _, pkt in read_packets(input_file):
        new_pkts.append(modify_mac_one_pkt(pkt, src_mac, dst_mac))
        if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
            wrpcap(output_file, new_pkts, append=True)
            # print(f"Written {len(new_pkts)} packets to {output_pcap}")
            new_pkts = []
    if new_pkts:
        wrpcap(output_file, new_pkts, append=True)
    print(f"[gen_pcap_flow_affinity_hhd] output pcap: {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output file name", required=True)
    parser.add_argument("--dst_mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")
    args = parser.parse_args()
    dst_mac = args.dst_mac
    gen_pcap_flow_affinity_hhd(dst_mac, args.output_path, args.input_file)
