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

def construct_packet_v1(sport, dport, client_mac, client_ip, server_mac, server_ip):
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw("123456789012")
    return packet

def construct_packet_v2(num, sport, dport, client_mac, client_ip, server_mac, server_ip):
    if ENABLE_DEBUG: print(f"num = {num}")
    seq = [100] * num
    if ENABLE_DEBUG: print("seq:", seq)
    dports_bytes = b''
    dports_bytes += num.to_bytes(2, 'little')
    for x in seq:
        dports_bytes += x.to_bytes(4, 'little')

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    if ENABLE_DEBUG: hexdump(packet)
    return packet

def convert_ipv4_str_to_int(ip):
    arr = ip.split('.')
    if len(arr) != 4:
        print(f"ERROR: invalid ip {ip}")
    ip_int = (int(arr[0]) << 24) | (int(arr[1]) << 16) | (int(arr[2]) << 8) | int(arr[3])
    return ip_int

def construct_packet_v3(sport, dport, client_mac, client_ip, server_mac, server_ip):
    protocol = 17 # udp
    client_ip_int = convert_ipv4_str_to_int(client_ip)
    server_ip_int = convert_ipv4_str_to_int(server_ip)
    flow1_bytes = b''
    flow1_bytes += protocol.to_bytes(4, 'little')
    flow1_bytes += client_ip_int.to_bytes(4, 'big') + server_ip_int.to_bytes(4, 'big')
    flow1_bytes += sport.to_bytes(2, 'little') + dport.to_bytes(2, 'little')

    dports_bytes = b''
    size = 100
    for _ in range(0, 7):
        dports_bytes += flow1_bytes
        dports_bytes += size.to_bytes(4, 'little')

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    if ENABLE_DEBUG: hexdump(packet)
    return packet

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Program used to generate pcap trace for the PortKnock example')
    parser.add_argument("-c", "--config-file", type=str, default=CONFIG_file_xl170, help="The Classbench trace input file")
    parser.add_argument("-v", '--version', default='v1', const='v1', nargs='?', choices=['v1', 'v2', 'v3'], help='v1 is for shared state, v2 is for local state')
    parser.add_argument("-o", "--output-file", type=str, default=f"{sys.path[0]}/generated_pcaps", help="The output pcap file")
    parser.add_argument("-n", "--num-cores", type=int, default=0, help="Number of cores")
    parser.add_argument("-s", "--src-ip", required=True, type=str, help="Src ip used for RSS")
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true', help="Print some debug information")

    args = parser.parse_args()

    version = args.version
    num_cores = args.num_cores

    if version == "v2" or version == "v3":
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
    SERVER_mac = read_machine_info_from_file(config_file, "server_mac")
    SERVER_ip = read_machine_info_from_file(config_file, "server_ip")
    SERVER_cpu = read_machine_info_from_file(config_file, "server_cpu")

    # sport and dport do not matter for intel/amd machines, so set them as what ARM machines requires
    sport = SPORT_ARM
    dport = DPORT_ARM

    num_pkts_in_md = NUM_cores - 1
    constructed_packet = ""

    if version == "v1":
        constructed_packet = construct_packet_v1(sport, dport, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    elif version == "v2":
        constructed_packet = construct_packet_v2(num_pkts_in_md, sport, dport, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    elif version == "v3":
        constructed_packet = construct_packet_v3(sport, dport, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)

    packets = 100 * constructed_packet

    with PcapWriter(args.output_file, append=True, sync=True) as pktdump:
        pktdump.write(packets)

    sys.exit(0)
