# version: v1, v2
# v1 is for shared state, v2 is for local state
# "# of cores" should be provided if version is v2

import argparse
from os.path import exists
import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandIP, RandString
from scapy.all import *

SPORT_ARM = 53
DPORT_ARM = 12
CONFIG_file_xl170 = f"{sys.path[0]}/config.xl170"
# # DPORT_SEQ won't be used for arm machines
DPORT_SEQ = [100, 101, 102]
PORT_START = 1
NUM_PORTS_IN_PAYLOAD = 7
PORT_PADDING = 0xffff # this port won't be processed by the xdp program, only used for padding
CPU_ARM = "arm"
CPU_INTEL = "intel"
CPU_AMD = "amd"

FLAG_LOOP = True
CLIENT_port = 2000
CLIENT_iface = ''
CLIENT_mac = ''
CLIENT_ip = ''
SERVER_mac = ''
SERVER_ip = ''
NUM_cores = 0
ENABLE_DEBUG = False

def read_machine_info_from_file(input_file, keyword):
    res = None
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Stop process...")
        sys.exit(0)
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(":", 1)
        if len(line) < 2:
            continue
        if line[0] == keyword:
            res = line[1].strip()
    f.close()
    if res is None:
        print(f"ERROR: no {keyword} in {input_file}. Stop process...")
        sys.exit(0)
    return res

    # n: the number of dport list
def all_dport_list(n):
    res = []
    if n == 0: 
        return [[]]
    elif n == 1:
        for x in DPORT_SEQ:
            res.append([x])
        return res

    dport_list = all_dport_list(n - 1)
    for dport in DPORT_SEQ:
        for x in dport_list:
            res.append([dport] + x)
    return res

# construct port sequences when num of ports < len(DPORT_SEQ)
# x + k(num_ports_in_md + 1) = len(DPORT_SEQ) + 1
def construct_port_sequences_few_num_ports(num_ports_in_md):
    res = []
    minimal_port_list_len = len(DPORT_SEQ) + 1
    dports_list = construct_port_sequences(minimal_port_list_len)
    num_ports_in_one_packet = num_ports_in_md + 1
    k = int(minimal_port_list_len / num_ports_in_one_packet)
    x = minimal_port_list_len - k * num_ports_in_one_packet
    num_padding = num_ports_in_md - (x - 1)
    # print(f"k = {k}, num_padding = {num_padding}")
    for dports in dports_list:
        if len(dports) < minimal_port_list_len:
            raise
        # the first list is with paddding
        if x > 0:
            l = num_padding * [PORT_PADDING] + dports[:x]
            res.append(l)
        for i in range(k):
            l = dports[x + i * num_ports_in_one_packet: x + (i + 1) * num_ports_in_one_packet]
            res.append(l)
    return res

# Create a list of knocking sequence + port used to check whether can be allowed
# only one sequence will open the server port, dport of the allowed is PORT_ALLOW
def construct_port_sequences(num_ports):
    if num_ports < len(DPORT_SEQ) + 1:
        return construct_port_sequences_few_num_ports(num_ports - 1)
    res = []
    dports_list = all_dport_list(num_ports - 1)
    for i, dports in enumerate(dports_list):
        res.append(dports + [PORT_START + i])
    if ENABLE_DEBUG:
        print(f"{len(res)} sequences:")
        for x in res:
            print(x)
    return res

def construct_packet(sport, dport, client_mac, client_ip, server_mac, server_ip):
    dports_bytes = PORT_PADDING.to_bytes(2, 'big') * NUM_PORTS_IN_PAYLOAD
    payload = (str(PORT_PADDING) + ", ") * NUM_PORTS_IN_PAYLOAD
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    # print(f"dport: {dport}, payload: {payload}")
    return packet

def construct_packet_v1(sport, client_mac, client_ip, server_mac, server_ip, server_cpu):
    packet_list = []
    dports_list = [[DPORT_ARM]]
    if not server_cpu == "arm":
        dports_list = construct_port_sequences(len(DPORT_SEQ) + 1)
    for dports in dports_list:
        for dport in dports:
            packet = construct_packet(sport, dport, client_mac, client_ip, server_mac, server_ip)
            packet_list.append(packet)
    return packet_list

def construct_packet_with_metadata(sport, dports, client_mac, client_ip, server_mac, server_ip, num_ports_in_md):
    dport = dports[-1]
    num_padding = NUM_PORTS_IN_PAYLOAD - num_ports_in_md

    payload = ""
    dports_bytes = b''
    for p in dports[:-1]:
        dports_bytes += p.to_bytes(2, 'big')
        payload += str(p) + ", "

    dports_bytes += PORT_PADDING.to_bytes(2, 'big') * num_padding
    if ENABLE_DEBUG:
        payload += (str(PORT_PADDING) + ", ") * num_padding
        print(f"dport: {dport}, payload: {payload}")

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    return packet

def construct_packet_v2(sport, client_mac, client_ip, server_mac, server_ip, server_cpu, num_ports_in_md):
    dports_list = [[DPORT_ARM]]
    if not server_cpu == "arm":
        dports_list = construct_port_sequences(num_ports_in_md + 1)
    packet_list = []
    if ENABLE_DEBUG:
        print(f"{len(dports_list)} sequences in packets: ")
        for dports in dports_list:
            print(dports)
    for dports in dports_list:
        packet = construct_packet_with_metadata(sport, dports, client_mac, client_ip, server_mac, server_ip, num_ports_in_md)
        packet_list.append(packet)
    return packet_list

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Program used to generate pcap trace for the PortKnock example')
    parser.add_argument("-c", "--config-file", required=True, type=str, help="The Classbench trace input file")
    parser.add_argument("-v", '--version', required=True, default='v1', const='v1', nargs='?', choices=['v1', 'v2'], help='v1 is for shared state, v2 is for local state')
    parser.add_argument("-o", "--output-file", type=str, default=f"{sys.path[0]}/generated_pcaps", help="The output pcap file")
    parser.add_argument("-n", "--num-cores", type=int, default=0, help="Number of cores")
    parser.add_argument("-s", "--src-ip", required=True, type=str, help="Src ip used for RSS")
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true', help="Print some debug information")

    args = parser.parse_args()

    version = args.version
    num_cores = args.num_cores

    if version == "v2":
        if num_cores <= 0:
            print("Please specify the number of cores")
            sys.exit(0)

    src_ip = args.src_ip
    config_file = args.config_file

    Path(args.output_file).mkdir(parents=True, exist_ok=True)

    ENABLE_DEBUG = args.debug

    NUM_cores = num_cores
    CLIENT_iface = read_machine_info_from_file(config_file, "client_iface")
    CLIENT_mac = read_machine_info_from_file(config_file, "client_mac")
    CLIENT_ip = src_ip
    CLIENT_port = SPORT_ARM
    SERVER_mac = read_machine_info_from_file(config_file, "server_mac")
    SERVER_ip = read_machine_info_from_file(config_file, "server_ip")
    SERVER_cpu = read_machine_info_from_file(config_file, "server_cpu")

    num_ports_in_md = NUM_cores - 1
    packet_list = list()
    if version == "v1":
        packet_list = construct_packet_v1(CLIENT_port, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip, SERVER_cpu)
    elif version == "v2":
        packet_list = construct_packet_v2(CLIENT_port, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip, SERVER_cpu, num_ports_in_md)

    with PcapWriter(args.output_file, append=True, sync=True) as pktdump:
        pktdump.write(packet_list)

    sys.exit(0)
