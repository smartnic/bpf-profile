import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
import os
import time
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


def gen_pcap_shared_state(num_cores, dst_mac, output_path, input_file):
    print(f"start [gen_pcap_shared_state] num_cores: {num_cores}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    # input_pkts = rdpcap(input_file)
    new_pkts = list()
    output_file = f"{output_path}/shared_state_{num_cores}.pcap"
    for i, curr_pkt in read_packets(input_file):
        # src_mac is used for rss
        src_mac = f"10:10:10:10:10:{format(i % num_cores, '02x')}"
        new_pkt = modify_mac_one_pkt(curr_pkt, src_mac, dst_mac)
        new_pkts.append(new_pkt)
        if len(new_pkts) >= PKTS_WRITE_SIZE:
            wrpcap(output_file, new_pkts, append=True)
            # print(f"Written {len(new_pkts)} packets to {output_pcap}")
            new_pkts = []
    if new_pkts:
        wrpcap(output_file, new_pkts, append=True)
        # print(f"Written {len(new_pkts)} packets to {output_pcap}")
    print(f"[gen_pcap_shared_state] output pcap: {output_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output file name", required=True)
    parser.add_argument("--num_cores", "-n", dest="num_cores", help="Number of cores used to process packets", type=int, default=1)
    parser.add_argument("--dst_mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")
    args = parser.parse_args()
    t_start = time.time()
    gen_pcap_shared_state(args.num_cores, args.dst_mac, args.output_path, args.input_file)
    time_cost = time.time() - t_start
    print(f"shared_state {args.num_cores} time_cost: {time_cost}")

