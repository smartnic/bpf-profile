# sudo python3 send_udp_packets_test.py [version] [sport] [# of cores]
# version: v1, v2
# v1 is for shared state, v2 is for local state
# "# of cores" should be provided if version is v2

import argparse
from os.path import exists
from scapy.all import*
import sys

CONFIG_file_xl170 = "config.xl170"
DPORT_SEQ = [100, 101, 102]
PORT_START = 1
NUM_PORTS_IN_PAYLOAD = 7
PORT_PADDING = 0xffff # this port won't be processed by the xdp program, only used for padding

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

# Create a list of knocking sequence + port used to check whether can be allowed
# only one sequence will open the server port, dport of the allowed is PORT_ALLOW
def construct_port_sequences(num_ports):
    res = []
    dports_list = all_dport_list(num_ports - 1)
    for i, dports in enumerate(dports_list):
        res.append(dports + [PORT_START + i])
    print(f"{len(res)} sequences:")
    for x in res:
        print(x)
    return res;

def construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    dports_bytes = PORT_PADDING.to_bytes(2, 'big') * NUM_PORTS_IN_PAYLOAD
    payload = (str(PORT_PADDING) + ", ") * NUM_PORTS_IN_PAYLOAD
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    print(f"dport: {dport}, payload: {payload}")
    return packet

def send_udp_packets_v1(sport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packet_list = []
    dports_list = construct_port_sequences(len(DPORT_SEQ) + 1)
    for dports in dports_list:
        for dport in dports:
            packet = construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
            packet_list.append(packet)
    sendpfast(packet_list, iface=client_iface)

def construct_packet_with_metadata(sport, dports, client_iface, client_mac, client_ip, server_mac, server_ip, num_ports_in_md):
    dport = dports[-1]
    num_padding = NUM_PORTS_IN_PAYLOAD - num_ports_in_md;

    payload = ""
    dports_bytes = b''
    for p in dports[:-1]:
        dports_bytes += p.to_bytes(2, 'big')
        payload += str(p) + ", "

    dports_bytes += PORT_PADDING.to_bytes(2, 'big') * num_padding
    payload += (str(PORT_PADDING) + ", ") * num_padding
    print(f"dport: {dport}, payload: {payload}")

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    return packet

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

def send_udp_packets_v2(sport, client_iface, client_mac, client_ip, server_mac, server_ip, num_ports_in_md):
    dports_list = []
    if num_ports_in_md < len(DPORT_SEQ):
        dports_list = construct_port_sequences_few_num_ports(num_ports_in_md)
    else:
        dports_list = construct_port_sequences(num_ports_in_md + 1)
    packet_list = []
    print(f"{len(dports_list)} sequences in packets: ")
    for dports in dports_list:
        print(dports)
    for dports in dports_list:
        packet = construct_packet_with_metadata(sport, dports, client_iface, client_mac, client_ip, server_mac, server_ip, num_ports_in_md)
        packet_list.append(packet)
    sendpfast(packet_list, iface=client_iface)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Please specify version and the source port.")
        sys.exit(0)

    version = sys.argv[1]
    if version != "v1" and version != "v2":
        print(f"Version {version} is not v1 or v2")
        sys.exit(0)
    num_cores = 0
    if version == "v2" and len(sys.argv) < 4:
        print("Please specify the number of cores")
        sys.exit(0)
    sport = int(sys.argv[2])
    if version == "v2":
        num_cores = int(sys.argv[3])
    print(f"version = {version}, sport = {sport}, number of cores = {num_cores}")
    num_ports_in_md = num_cores - 1

    client_iface = read_machine_info_from_file("client_iface")
    client_mac = read_machine_info_from_file("client_mac")
    client_ip = read_machine_info_from_file("client_ip")
    server_mac = read_machine_info_from_file("server_mac")
    server_ip = read_machine_info_from_file("server_ip")
    print(client_iface, client_mac, client_ip, server_mac, server_ip)
    if version == "v1":
        send_udp_packets_v1(sport, client_iface, client_mac, client_ip, server_mac, server_ip)
    elif version == "v2":
        send_udp_packets_v2(sport, client_iface, client_mac, client_ip, server_mac, server_ip, num_ports_in_md)
