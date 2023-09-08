import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
from gen_pcap_utils import *
import os

NO_TCP_FLAGS = 0
TCP_SYN = 1
TCP_FIN = 2

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
    keys = list(stats.keys())
    keys.sort()
    output_file = f"{output_path}/stats.txt"
    with open(output_file, "w") as file:
        file.write(f"{len(keys)} flows\n")
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


def get_pkts_modify_dic(stats):
    pkts_modify_dic = {}
    for val in stats.values():
        pkts_modify_dic[val.first_pkt] = TCP_SYN
        pkts_modify_dic[val.last_pkt] = TCP_FIN
    return pkts_modify_dic


def update_tcp_flags(pkts_modify_dic, pkt, idx):
    if not pkt.haslayer(TCP):
        return
    flag = NO_TCP_FLAGS
    if idx in pkts_modify_dic:
        flag = pkts_modify_dic[idx]
    if flag == TCP_SYN:
        pkt[TCP].flags = 'S'
    elif flag == TCP_FIN:
        pkt[TCP].flags = 'F'
    else:
        pkt[TCP].flags = 'A'
    return pkt


def truncate_tcp_pkts_and_stats(input_file, output_path, output_filename, max_pkt_size):
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    new_pkts = list()
    output_file = f"{output_path}/{output_filename}"
    append_flag = False
    stats = {}
    for idx, curr_pkt in read_packets(input_file):
        if not curr_pkt.haslayer(IP):
            continue
        if not curr_pkt.haslayer(TCP):
            continue
        stats = get_stats_one_pkt(stats, curr_pkt, idx)

    pkts_modify_dic = get_pkts_modify_dic(stats)
    for idx, curr_pkt in read_packets(input_file):
        if not curr_pkt.haslayer(IP):
            continue
        if not curr_pkt.haslayer(TCP):
            continue
        new_pkt = truncate_tcp_pkt(curr_pkt, max_pkt_size)
        new_pkt = update_tcp_flags(pkts_modify_dic, new_pkt, idx)
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

