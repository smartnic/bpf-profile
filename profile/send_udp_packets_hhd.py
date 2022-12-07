import argparse
from os.path import exists
from scapy.all import*
import sys
from os.path import expanduser

home = expanduser("~")
CONFIG_file_xl170 = f"{home}/bpf-profile/profile/config.xl170"

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
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw("123456789012")
    return packet

def construct_packet_v2(num, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    print(f"num = {num}")
    seq = [100] * num
    print("seq:", seq)
    dports_bytes = b''
    dports_bytes += num.to_bytes(2, 'little')
    for x in seq:
        dports_bytes += x.to_bytes(4, 'little')

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    hexdump(packet)
    return packet

def convert_ipv4_str_to_int(ip):
    arr = ip.split('.')
    if len(arr) != 4:
        print(f"ERROR: invalid ip {ip}")
    ip_int = (int(arr[0]) << 24) | (int(arr[1]) << 16) | (int(arr[2]) << 8) | int(arr[3])
    return ip_int

# metadata element: | pkt_i flow | pkt_i length |
# struct flow_key {
#   u8 protocol;
#   __be32 src_ip;
#   __be32 dst_ip;
#   u16 src_port;
#   u16 dst_port;
# };
def construct_packet_v3(num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    protocol = 17 # udp
    client_ip_int = convert_ipv4_str_to_int(client_ip)
    server_ip_int = convert_ipv4_str_to_int(server_ip)
    flow1_bytes = b''
    flow1_bytes += protocol.to_bytes(4, 'little')
    flow1_bytes += client_ip_int.to_bytes(4, 'big') + server_ip_int.to_bytes(4, 'big')
    flow1_bytes += sport.to_bytes(2, 'little') + dport.to_bytes(2, 'little')

    dports_bytes = b''
    size = 100
    for i in range(num_pkts_in_md):
        dports_bytes += flow1_bytes
        dports_bytes += size.to_bytes(4, 'little')

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    return packet

def send_udp_packets(version, num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packet = ""
    if version == "v1":
        packet = construct_packet_v1(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    elif version == "v2":
        packet = construct_packet_v2(num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    elif version == "v3":
        packet = construct_packet_v3(num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)

    # sendpfast(packet, iface=client_iface)
    packets = 100 * packet
    sendpfast(packets, iface=client_iface, pps=1000000, loop=1000000000)

# src_ip is used for RSS
def set_up_arguments(num_cores, src_ip):
    global CLIENT_iface, CLIENT_mac, CLIENT_ip, CLIENT_port, SERVER_mac, SERVER_ip, SERVER_port
    NUM_cores = num_cores
    CLIENT_iface = read_machine_info_from_file("client_iface")
    CLIENT_mac = read_machine_info_from_file("client_mac")
    CLIENT_ip = src_ip
    CLIENT_port = SPORT_ARM
    SERVER_mac = read_machine_info_from_file("server_mac")
    SERVER_ip = read_machine_info_from_file("server_ip")
    SERVER_port = DPORT_ARM

def hhd_construct_packets(version, src_ip, num_cores = 0):
    set_up_arguments(num_cores, src_ip)
    packet = ""
    if version == "v1":
        packet = construct_packet_v1(CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    elif version == "v2":
        packet = construct_packet_v2(num_cores-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    elif version == "v3":
        packet = construct_packet_v3(num_cores-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    return [packet]

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Please specify version, src ip, and number of cores.")
        sys.exit(0)

    version = sys.argv[1]
    if version not in ["v1", "v2", "v3"]:
        print(f"Version {version} is not v1, v2, or v3")
        sys.exit(0)
    src_ip = sys.argv[2]
    num_cores = int(sys.argv[3])

    set_up_arguments(num_cores, src_ip)
    num_pkts_in_md = NUM_cores - 1
    # print(version, src_mac, src_ip, num_cores)

    send_udp_packets(version, num_pkts_in_md, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
