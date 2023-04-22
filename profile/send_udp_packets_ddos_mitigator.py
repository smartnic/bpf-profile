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
EXTERNAL_PKT_SIZE = 64 # in bytes

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

def convert_ipv4_str_to_int(ip):
    arr = ip.split('.')
    if len(arr) != 4:
        print(f"ERROR: invalid ip {ip}")
    ip_int = (int(arr[0]) << 24) | (int(arr[1]) << 16) | (int(arr[2]) << 8) | int(arr[3])
    return ip_int

def construct_packet_v1(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    print(client_iface, client_mac, client_ip, sport, server_mac, server_ip, dport)
    ext_pkt = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)
    ext_pkt /= 'x' * max(0, EXTERNAL_PKT_SIZE - len(ext_pkt))
    print(f"packet size: {len(ext_pkt)} bytes")
    return ext_pkt

def construct_packets_v3(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
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

# struct metadata_elem {
#   __be16 ethtype;
#   __be32 ipv4_addr;
# } __attribute__((packed));
# use src ip for ipv4_addr
def construct_packets_v4(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    ethtype = ETH_P_IP
    client_ip_int = convert_ipv4_str_to_int(client_ip)
    load_bytes = b''
    for _ in range(num_pkts_in_md):
        load_bytes += ethtype.to_bytes(2, 'big')
        load_bytes += client_ip_int.to_bytes(4, 'big')
    ext_pkt = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)
    ext_pkt /= 'x' * max(0, EXTERNAL_PKT_SIZE - len(ext_pkt))
    packet = Ether(src=client_mac,dst=server_mac,type=ethtype)/Raw(load=load_bytes)/ext_pkt
    print(f"packet size: {len(packet)} bytes")
    return [packet]

def send_udp_packets(version, num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packets = []
    if version == "v1":
        packet = construct_packet_v1(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
        packets.append(packet)
    elif version == "v3":
        packets = construct_packets_v3(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    elif version == "v4":
        packets = construct_packets_v4(num_cores-1, num_flows-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    sendp(packets, iface=client_iface)
    # # packets = 100 * packet
    # sendpfast(packets, iface=client_iface, pps=1000000, loop=1)

# src_mac is used for RSS
def set_up_arguments(num_cores, src_mac, num_flows, ext_pkt_size):
    global NUM_cores, NUM_flows, CLIENT_iface, CLIENT_mac, CLIENT_ip, CLIENT_port, SERVER_mac, SERVER_ip, SERVER_port
    global EXTERNAL_PKT_SIZE
    NUM_cores = num_cores
    NUM_flows = num_flows
    CLIENT_iface = read_machine_info_from_file("client_iface")
    CLIENT_mac = src_mac
    CLIENT_ip = "10.10.1.0"
    CLIENT_port = SPORT_ARM
    SERVER_mac = read_machine_info_from_file("server_mac")
    SERVER_ip = read_machine_info_from_file("server_ip")
    SERVER_port = DPORT_ARM
    EXTERNAL_PKT_SIZE = ext_pkt_size

def ddos_mitigator_construct_packets(version, src_mac, num_cores = 0, num_flows = 1, ext_pkt_size = 64):
    set_up_arguments(num_cores, src_mac, num_flows, ext_pkt_size)
    packets = []
    packet = ""
    if version == "v1" or version == "v2":
        packet = construct_packet_v1(CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
        packets.append(packet)
    elif version == "v3":
        packets = construct_packets_v3(num_cores-1, num_flows-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    elif version == "v4":
        packets = construct_packets_v4(num_cores-1, num_flows-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    return packets

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Please specify version, src ip, number of cores, [number of flow], [ext_pkt_size]")
        sys.exit(0)

    version = sys.argv[1]
    if version not in ["v1", "v2", "v3", "v4"]:
        print(f"Version {version} is not v1 - v4")
        sys.exit(0)
    src_mac = sys.argv[2]
    num_cores = int(sys.argv[3])
    num_flows = 1
    if len(sys.argv) >= 5:
        num_flows = int(sys.argv[4])
    if num_flows <= 1:
        num_flows = 1

    ext_pkt_size = 64
    if len(sys.argv) >= 6:
        ext_pkt_size = int(sys.argv[5])    
    set_up_arguments(num_cores, src_mac, num_flows, ext_pkt_size)
    num_pkts_in_md = NUM_cores - 1
    num_flows_in_md = num_flows - 1
    # print(version, src_mac, src_ip, num_cores)

    send_udp_packets(version, num_pkts_in_md, num_flows_in_md, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
