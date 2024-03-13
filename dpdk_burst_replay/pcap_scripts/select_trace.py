"""
    Select traces from open-sourced dataset
"""
import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import os
import argparse
from gen_pcap_utils import *
from typing import Tuple, List
import collections

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


# Generator function to read and yield packets one by one
def read_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet_number, packet in enumerate(pcap_reader, start=0):
            yield packet_number, packet


def select_trace_idx_range(
    packet_labels: List[int], max_flow_count: int
) -> Tuple[int, int]:
    if len(packet_labels) <= 0 or max_flow_count <= 0:
        raise AssertionError("Invalid input")

    range_start, range_end = 0, 0
    start_idx = 0
    flow_id_map_pkt_count_within_range = collections.defaultdict(int)

    for end_index, flow_id in enumerate(packet_labels):
        flow_id_map_pkt_count_within_range[flow_id] += 1

        if len(flow_id_map_pkt_count_within_range) > max_flow_count:
            # st
            while (
                start_idx < end_index
                and len(flow_id_map_pkt_count_within_range) > max_flow_count
            ):
                flow_id_map_pkt_count_within_range[packet_labels[start_idx]] -= 1
                if flow_id_map_pkt_count_within_range[packet_labels[start_idx]] == 0:
                    flow_id_map_pkt_count_within_range.pop(
                        packet_labels[start_idx], None
                    )
                start_idx += 1

        if end_index - start_idx > range_end - range_start:
            range_start, range_end = start_idx, end_index

    return range_start, range_end


def get_packet_labels_from_pcap_file(pcap_file, output_path, max_flow_count):
    packet_labels = []
    label_dic = {}
    next_flow_idx = 0
    for _, curr_pkt in read_packets(pcap_file):
        key = get_flow_key(curr_pkt)
        if key in label_dic:
            packet_labels.append(label_dic[key])
        else:
            packet_labels.append(next_flow_idx)
            label_dic[key] = next_flow_idx
            next_flow_idx += 1
    range_start, range_end = select_trace_idx_range(packet_labels, max_flow_count)
    print(f"{max_flow_count}: {range_end-range_start+1} [{range_start}, {range_end}]")

    if not os.path.exists(output_path):
        os.makedirs(output_path)
    output_file = f"{output_path}/packet_labels.txt"
    with open(output_file, 'w') as file:
        for x in packet_labels:
            file.write(str(x) + '\n')
        print(f"packet labels output: {output_file}")

    new_pkts = []
    append_flag = False
    output_file = f"{output_path}/pkts_{max_flow_count}.pcap"
    for idx, curr_pkt in read_packets(pcap_file):
        if idx < range_start:
            continue
        elif idx > range_end:
            break
        new_pkts.append(curr_pkt)
        if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
            wrpcap(output_file, new_pkts, append=append_flag)
            new_pkts = []
            append_flag = True
    if new_pkts:
        wrpcap(output_file, new_pkts, append=append_flag)
    print(f"[select packet trace] output pcap: {output_path}")


if __name__ == "__main__":
    packet_labels = [1, 2, 2, 1, 1, 3, 3, 1, 1, 4, 4, 2, 1, 1]
    max_flow_count = 3
    range_start, range_end = select_trace_idx_range(packet_labels, max_flow_count)
    print(range_start, range_end)
    print(packet_labels[range_start: range_end+1])
    # pcap_file = "/common/home/qx51/caida_pkt_trace/caida/pcap/pt4/192/pkts.pcap"
    # output_path = "tmp4/"
    # max_flow_count = 200
    # get_packet_labels_from_pcap_file(pcap_file, output_path, max_flow_count)

