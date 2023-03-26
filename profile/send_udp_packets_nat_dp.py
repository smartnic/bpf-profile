import argparse
from os.path import exists
from scapy.all import*
import sys
from os.path import expanduser
from config import *

CONFIG_file_xl170 = f"{client_dir}/bpf-profile/profile/config.xl170"

SPORT_ARM = 53
DPORT_ARM = 12
CPU_ARM = "arm"
CPU_INTEL = "intel"
CPU_AMD = "amd"

CLIENT_iface = ''
CLIENT_mac = ''
CLIENT_ip = ''
CLIENT_port = 2000
SERVER_mac = ''
SERVER_ip = ''
SERVER_port = 2000
NUM_cores = 0
NUM_flows = 0

def read_machine_info_from_file(keyword):
    input_file = CONFIG_file_xl170
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

def construct_packet_v1(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    print(client_iface, client_mac, client_ip, sport, server_mac, server_ip, dport)
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw("123456789012")
    return packet

def construct_packets_v2(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    if num_flows_in_md != 0:
        print("ERROR: num flows cannot > 1")
        sys.exit(0)
    packet = None
    size = 100
    pkt_size_bytes = size.to_bytes(4, 'little')
    time = 100000000
    for _ in range(num_pkts_in_md + 1):
        time_bytes = time.to_bytes(8, 'little')
        time += 1024
        load_bytes = pkt_size_bytes + time_bytes
        if packet is None:
            packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=load_bytes)
        else:
            packet = packet/Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=load_bytes)
    return [packet]



def send_udp_packets(version, num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packets = []
    if version == "v1":
        packet = construct_packet_v1(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
        packets.append(packet)
    elif version == "v3":
        packets = construct_packets_v3(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    sendp(packets, iface=client_iface)
    # # packets = 100 * packet
    # sendpfast(packets, iface=client_iface, pps=1000000, loop=1)

# src_ip is used for RSS
def set_up_arguments(num_cores, src_ip, num_flows):
    global NUM_cores, NUM_flows, CLIENT_iface, CLIENT_mac, CLIENT_ip, CLIENT_port, SERVER_mac, SERVER_ip, SERVER_port
    NUM_cores = num_cores
    NUM_flows = num_flows
    CLIENT_iface = read_machine_info_from_file("client_iface")
    CLIENT_mac = read_machine_info_from_file("client_mac")
    CLIENT_ip = src_ip
    CLIENT_port = SPORT_ARM
    SERVER_mac = read_machine_info_from_file("server_mac")
    SERVER_ip = read_machine_info_from_file("server_ip")
    SERVER_port = DPORT_ARM

def nat_dp_construct_packets(version, src_ip, num_cores = 0, num_flows = 1):
    set_up_arguments(num_cores, src_ip, num_flows)
    packets = []
    packet = ""
    if version == "v1" :
        packet = construct_packet_v1(CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
        packets.append(packet)
    elif version == "v2":
        packets = construct_packets_v2(num_cores-1, num_flows-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    return packets

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Please specify version, src ip, number of cores")
        sys.exit(0)

    version = sys.argv[1]
    if version not in ["v1", "v2"]:
        print(f"Version {version} is not v1 or v2")
        sys.exit(0)
    src_ip = sys.argv[2]
    num_cores = int(sys.argv[3])
    num_flows = 1
    if len(sys.argv) >= 5:
        num_flows = int(sys.argv[4])
    if num_flows <= 1:
        num_flows = 1

    set_up_arguments(num_cores, src_ip, num_flows)
    num_pkts_in_md = NUM_cores - 1
    num_flows_in_md = num_flows - 1
    # print(version, src_mac, src_ip, num_cores)

    send_udp_packets(version, num_pkts_in_md, num_flows_in_md, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
