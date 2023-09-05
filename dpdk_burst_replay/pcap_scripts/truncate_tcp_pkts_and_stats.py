import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
from gen_pcap_utils import *
import os

def get_stats_one_pkt(stats, pkt):
    pkt_len = len(pkt)
    if pkt_len in stats.keys():
        stats[pkt_len] += 1
    else:
        stats[pkt_len] = 1
    return stats

def write_stats(stats, output_path):
    keys = list(stats.keys())
    keys.sort()
    output_file = f"{output_path}/stats.txt"
    with open(output_file, "w") as file:
        file.write(f"pkt size: number\n")
        for k in keys:
            file.write(f"{k}: {stats[k]}\n")

def extract_header_payload(input_pkts):
    header_list = []
    payload_list = []
    for pkt in input_pkts:
        if not pkt.haslayer(TCP):
            print("ERROR: not tcp packet")
            continue
        tcp = pkt[TCP]
        payload_list.append(bytes(tcp.payload))
        tcp.remove_payload()
        header_list.append(pkt)
    return header_list, payload_list

# Generator function to read and yield packets one by one
def read_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet_number, packet in enumerate(pcap_reader, start=0):
            yield packet_number, packet

def truncate_tcp_pkt(pkt, max_pkt_size):
    del pkt[TCP].options
    if len(pkt) <= max_pkt_size:
        return pkt
    if not pkt.haslayer(Ether):
        return None
    if not pkt.haslayer(IP):
        return None
    if not pkt.haslayer(TCP):
        return None
    max_payload_len = len(pkt[Raw].load) - (len(pkt) - max_pkt_size)
    pkt[Raw].load = pkt[Raw].load[:max_payload_len]
    pkt[IP].len = max_pkt_size - len(Ether())
    return pkt


def truncate_tcp_pkts_and_stats(input_file, output_path, output_filename, max_pkt_size):
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    new_pkts = list()
    output_file = f"{output_path}/{output_filename}"
    append_flag = False
    stats = {}
    for _, curr_pkt in read_packets(input_file):
        new_pkt = truncate_tcp_pkt(curr_pkt, max_pkt_size)
        stats = get_stats_one_pkt(stats, new_pkt)
        if new_pkt:
            new_pkts.append(new_pkt)
        if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
            wrpcap(output_file, new_pkts, append=append_flag)
            new_pkts = []
            append_flag = True
    if new_pkts:
        wrpcap(output_file, new_pkts, append=append_flag)
    print(f"[truncate_tcp_pkts_and_stats] output pcap: {output_path}")
    write_stats(stats, output_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output path name", required=True)
    parser.add_argument("--output_fname", dest="output_filename", help="Output file name", required=True)
    parser.add_argument("--max_pkt_size", "-s", dest="max_pkt_size", type=int, help="Max pkt size", required=True)
    args = parser.parse_args()
    truncate_tcp_pkts_and_stats(args.input_file, args.output_path, args.output_filename, args.max_pkt_size)

