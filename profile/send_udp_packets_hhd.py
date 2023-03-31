import argparse
from os.path import exists
from scapy.all import*
import sys
from os.path import expanduser
from config import client_dir

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
#   __be32 src_ip;
#   __be32 dst_ip;
#   u16 src_port;
#   u16 dst_port;
#   u8 protocol;
# };
def construct_packet_v3(num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    protocol = 17 # udp
    client_ip_int = convert_ipv4_str_to_int(client_ip)
    server_ip_int = convert_ipv4_str_to_int(server_ip)

    dports_bytes = b''
    size = 100
    for i in range(num_pkts_in_md):
        client_ip_int += 9
        print("client_ip_int: ", client_ip_int)
        flow1_bytes = b''
        # flow1_bytes += protocol.to_bytes(4, 'little')
        flow1_bytes += client_ip_int.to_bytes(4, 'big') + server_ip_int.to_bytes(4, 'big')
        flow1_bytes += sport.to_bytes(2, 'little') + dport.to_bytes(2, 'little')
        flow1_bytes += protocol.to_bytes(4, 'little')
        dports_bytes += flow1_bytes
        dports_bytes += size.to_bytes(4, 'little')

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    return packet

# num_flows_in_md = # of flows - 1, 1 is the packet itself.
def construct_packets_v6(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    protocol = 17 # udp
    client_ip_int = convert_ipv4_str_to_int(client_ip)
    server_ip_int = convert_ipv4_str_to_int(server_ip)

    size = 100
    packets = []
    if num_pkts_in_md == 0:
        dports_bytes = b''
        strHex = "0x%0.8X" % client_ip_int
        print(f"packet client_ip_int: {client_ip_int}, {strHex}")
        packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
        packets.append(packet)
        return packets

    if num_flows_in_md == 0:
        strHex = "0x%0.8X" % client_ip_int
        print(f"packet client_ip_int: {client_ip_int}, {strHex}")
        dports_bytes = b''
        for i in range(num_pkts_in_md):
            flow1_bytes = b''
            # flow1_bytes += protocol.to_bytes(4, 'little')
            flow1_bytes += protocol.to_bytes(1, 'little')
            flow1_bytes += client_ip_int.to_bytes(4, 'big') + server_ip_int.to_bytes(4, 'big')
            flow1_bytes += sport.to_bytes(2, 'little') + dport.to_bytes(2, 'little')
            dports_bytes += flow1_bytes
            dports_bytes += size.to_bytes(4, 'little')
        packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
        packets.append(packet) 
        return packets

    for pkt_id in range(num_flows_in_md):
        client_ip_int += 9
        strHex = "0x%0.8X" % client_ip_int
        print(f"packet {pkt_id} client_ip_int: {client_ip_int}, {strHex}")
        dports_bytes = b''
        for i in range(num_pkts_in_md):
            flow1_bytes = b''
            # flow1_bytes += protocol.to_bytes(4, 'little')
            flow1_bytes += protocol.to_bytes(1, 'little')
            flow1_bytes += client_ip_int.to_bytes(4, 'big') + server_ip_int.to_bytes(4, 'big')
            flow1_bytes += sport.to_bytes(2, 'little') + dport.to_bytes(2, 'little')
            dports_bytes += flow1_bytes
            dports_bytes += size.to_bytes(4, 'little')
        packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
        packets.append(packet)
    # hexdump(packet)
    return packets

def construct_packets_v9(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    if num_flows_in_md != 0:
        print("ERROR: num flows cannot > 1")
        sys.exit(0)
    packet = None
    size = 100
    pkt_size_bytes = size.to_bytes(4, 'little')
    for _ in range(num_pkts_in_md + 1):
        if packet is None:
            packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=pkt_size_bytes)
        else:
            packet = packet/Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=pkt_size_bytes)
    return [packet]



def send_udp_packets(version, num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packets = []
    if version == "v1" or version == "v5" or version == "v4":
        packet = construct_packet_v1(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
        packets.append(packet)
    elif version == "v2":
        packet = construct_packet_v2(num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
        packets.append(packet)
    elif version == "v3":
        packet = construct_packet_v3(num_pkts_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
        packets.append(packet)
    elif version == "v6" or version == "v7" or version == "v8":
        packets = construct_packets_v6(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    elif version == "v9":
        packets = construct_packets_v9(num_pkts_in_md, num_flows_in_md, sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    # sendpfast(packet, iface=client_iface)
    # packets = 100 * packet
    sendpfast(packets, iface=client_iface, pps=1000000, loop=1)

# src_ip is used for RSS
def set_up_arguments(num_cores, src_ip, num_flows):
    global NUM_cores, CLIENT_iface, CLIENT_mac, CLIENT_ip, CLIENT_port, SERVER_mac, SERVER_ip, SERVER_port
    NUM_cores = num_cores
    NUM_flows = num_flows
    CLIENT_iface = read_machine_info_from_file("client_iface")
    CLIENT_mac = read_machine_info_from_file("client_mac")
    CLIENT_ip = src_ip
    CLIENT_port = SPORT_ARM
    SERVER_mac = read_machine_info_from_file("server_mac")
    SERVER_ip = read_machine_info_from_file("server_ip")
    SERVER_port = DPORT_ARM

def hhd_construct_packets(version, src_ip, num_cores = 0, num_flows = 1):
    set_up_arguments(num_cores, src_ip, num_flows)
    packets = []
    packet = ""
    if version == "v1" or version == "v5" or version == "v4":
        packet = construct_packet_v1(CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
        packets.append(packet)
    elif version == "v2":
        packet = construct_packet_v2(num_cores-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
        packets.append(packet)
    elif version == "v3":
        packet = construct_packet_v3(num_cores-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
        packets.append(packet)
    elif version == "v6" or version == "v7" or version == "v8" or version == "v10":
        packets = construct_packets_v6(num_cores-1, num_flows-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    elif version == "v9":
        packets = construct_packets_v9(num_cores-1, num_flows-1, CLIENT_port, SERVER_port, CLIENT_iface, CLIENT_mac, CLIENT_ip, SERVER_mac, SERVER_ip)
    return packets

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Please specify version, src ip, number of cores")
        sys.exit(0)

    version = sys.argv[1]
    if version not in ["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10"]:
        print(f"Version {version} is not v1 - v9")
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
