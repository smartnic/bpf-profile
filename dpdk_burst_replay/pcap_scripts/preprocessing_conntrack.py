import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
from gen_pcap_utils import *
import os
from ccdf import ccdf
import numpy as np

NO_TCP_FLAGS = 0
TCP_SYN = 1
TCP_FIN = 2
NO_LIMIT_n_flows = -1

class FlowKey():
    def __init__(self):
        self.protocol = 0
        self.src_ip = 0
        self.dst_ip = 0
        self.src_port = 0
        self.dst_port = 0

    def __str__(self):
        str = f"{self.protocol}: "
        str += f"{ipaddress.IPv4Address(self.src_ip)} "
        str += f"{self.src_port} -> "
        str += f"{ipaddress.IPv4Address(self.dst_ip)} "
        str += f"{self.dst_port}"
        return str

    def __hash__(self):
        # Define a custom hash function
        return hash((self.protocol, self.src_ip,
            self.dst_ip, self.src_port, self.dst_port))

    def __eq__(self, other):
        # Define custom equality comparison
        return (self.protocol == other.protocol and
                self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port)

    def __lt__(self, other):
        # Implement comparison logic for ordering
        if self.protocol != other.protocol:
            return self.protocol < other.protocol
        elif self.src_ip != other.src_ip:
            return self.src_ip < other.src_ip
        elif self.dst_ip != other.dst_ip:
            return self.dst_ip < other.dst_ip
        elif self.src_port != other.src_port:
            return self.src_port < other.src_port
        else:
            return self.dst_port < other.dst_port

class FlowVal():
    def __init__(self):
        self.num_pkts = 0
        self.first_pkt = None
        self.last_pkt = None

    def __str__(self):
        str = f"num_pkts: {self.num_pkts}, "
        str += f"first_pkt: {self.first_pkt}, "
        str += f"last_pkt: {self.last_pkt}"
        return str

    def __lt__(self, other):
        return self.num_pkts <= other.num_pkts


def get_flow_key(pkt):
    flow_key = FlowKey()
    flow_key.src_ip = int(ipaddress.ip_address(pkt.getlayer(IP).src))
    flow_key.dst_ip = int(ipaddress.ip_address(pkt.getlayer(IP).dst))
    if pkt.haslayer(TCP):
        flow_key.protocol = socket.IPPROTO_TCP
        flow_key.src_port = pkt.getlayer(TCP).sport
        flow_key.dst_port = pkt.getlayer(TCP).dport
    elif pkt.haslayer(UDP):
        flow_key.protocol = socket.IPPROTO_UDP
        flow_key.src_port = pkt.getlayer(UDP).sport
        flow_key.dst_port = pkt.getlayer(UDP).dport
    else:
        print(f"Unsupported layer type: {pkt.getlayer(IP).proto}")
        return None
    return flow_key


def get_stats_one_pkt(stats, pkt, idx):
    flow_key = get_flow_key(pkt)
    if flow_key not in stats:
        flow_val = FlowVal()
        flow_val.num_pkts = 1
        flow_val.first_pkt = idx
        flow_val.last_pkt = idx
        stats[flow_key] = flow_val
    else:
        stats[flow_key].num_pkts += 1
        stats[flow_key].last_pkt = idx
    return stats


def write_stats(stats, output_path):
    # Sort the dictionary based on values in descending order
    sorted_dict = dict(sorted(stats.items(), key=lambda item: item[1], reverse=True))
    packet_counts = []
    for _, v in sorted_dict.items():
        packet_counts.append(v.num_pkts)
    total_pkts = sum(packet_counts)
    ccdf(np.array(packet_counts), f"{output_path}/ccdf_conntrack.pdf", "flows")
    output_file = f"{output_path}/stats_conntrack.txt"
    accumulative_pkts = 0
    with open(output_file, "w") as file:
        file.write(f"{len(sorted_dict)} flows, {total_pkts} packets\n")
        for k in sorted_dict.keys():
            n_pkts = stats[k].num_pkts
            accumulative_pkts += n_pkts
            accumulative_pkts_percent = accumulative_pkts / total_pkts
            file.write(f"{k}: {stats[k]} {accumulative_pkts_percent}\n")
    return sorted_dict


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

def create_new_tcp_pkt(pkt):
    flow_key = get_flow_key(pkt)
    if not flow_key:
        return None
    src_ip = f"{ipaddress.IPv4Address(flow_key.src_ip)}"
    dst_ip = f"{ipaddress.IPv4Address(flow_key.dst_ip)}"
    new_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB", type=0x0800) / \
              IP(src=src_ip, dst=dst_ip, proto=6) / \
              TCP(sport=flow_key.src_port, dport=flow_key.dst_port, flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack)
    new_pkt.time = pkt.time
    return new_pkt


def preprocessing_conntrack(input_file, output_path, output_filename, n_flows):
    print(f"[preprocessing_conntrack] {input_file} {n_flows}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    new_pkts = list()
    output_file = f"{output_path}/{output_filename}"
    stats = {}
    for idx, curr_pkt in read_packets(input_file):
        if not curr_pkt.haslayer(IP):
            continue
        if not curr_pkt.haslayer(TCP):
            continue
        stats = get_stats_one_pkt(stats, curr_pkt, idx)
    # Sort the dictionary based on values in descending order
    sorted_flow_dic = dict(sorted(stats.items(), key=lambda item: item[1], reverse=True))
    if n_flows == NO_LIMIT_n_flows or n_flows > len(sorted_flow_dic):
        n_flows = len(sorted_flow_dic)
    # filered_flows = list(sorted_flow_dic.keys())[:n_flows]
    # filtered_flows_stats = {}
    # for flow in filered_flows:
    #     filtered_flows_stats[flow] = stats[flow]
    # use sample
    filered_flows = []
    filtered_flows_stats = {}
    gap = int(len(sorted_flow_dic) / n_flows)
    sorted_flows = list(sorted_flow_dic.keys())
    for i in range(n_flows):
        filered_flows.append(sorted_flows[i*gap])
    for flow in filered_flows:
        filtered_flows_stats[flow] = stats[flow]

    append_flag = False
    for idx, curr_pkt in read_packets(input_file):
        if not curr_pkt.haslayer(IP):
            continue
        if not curr_pkt.haslayer(TCP):
            continue
        flow = get_flow_key(curr_pkt)
        if flow not in filered_flows:
            continue
        new_pkt = create_new_tcp_pkt(curr_pkt)
        if new_pkt:
            new_pkts.append(new_pkt)
        if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
            wrpcap(output_file, new_pkts, append=append_flag)
            new_pkts = []
            append_flag = True
    if new_pkts:
        wrpcap(output_file, new_pkts, append=append_flag)
    print(f"[preprocessing_conntrack] output pcap: {output_path}")
    write_stats(filtered_flows_stats, output_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output path name", required=True)
    parser.add_argument("--output_fname", dest="output_filename", help="Output file name", required=True)
    parser.add_argument("--max_flows", dest="n_flows", help="Max number of flows", type=int, default=-1)
    args = parser.parse_args()
    preprocessing_conntrack(args.input_file, args.output_path, args.output_filename, args.n_flows)

