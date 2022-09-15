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
PORT_DENY = 1111
PORT_ALLOW = 2222

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
def dport_permutation(n):
    res = []
    if n == 0: 
        return [[]]
    elif n == 1:
        for x in DPORT_SEQ:
            res.append([x])
        return res

    dport_list = dport_permutation(n - 1)
    for dport in DPORT_SEQ:
        for x in dport_list:
            res.append([dport] + x)
    return res

# Create a list of knocking sequence + port used to check whether can be allowed
# only one sequence will open the server port, dport of the allowed is PORT_ALLOW
def construct_port_sequences(num_ports):
    res = []
    port_deny = PORT_DENY
    port_allow = PORT_ALLOW
    dports_list = dport_permutation(num_ports - 1)
    for dports in dports_list:
        # if the knocking sequence is correct, set the port as PORT_ALLOW
        x = len(DPORT_SEQ)
        if dports[-x:] == DPORT_SEQ:
            res.append(dports + [port_allow]) # knocking sequence + port_allow
        else:
            res.append(dports + [port_deny]) # knocking sequence + port_deny
    print(f"{len(res)} packet sequences:")
    for x in res:
        print(x)
    return res;

def construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    payload=b'\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77'
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=payload)
    # hexdump(packet)
    return packet

def send_udp_packets_v1(sport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packet_list = []
    dports_list = construct_port_sequences(len(DPORT_SEQ) + 1)
    for dports in dports_list:
        for dport in dports:
            packet = construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
            packet_list.append(packet)
    sendpfast(packet_list, iface=client_iface)

def construct_packet_with_metadata(sport, dports, client_iface, client_mac, client_ip, server_mac, server_ip, num_data):
    dport = dports[-1]
    port_padding = 0xffff # this port won't be used
    num_padding = 7 - num_data;

    dports_bytes = b''
    for p in dports[:-1]:
        dports_bytes += p.to_bytes(2, 'big')

    dports_bytes += port_padding.to_bytes(2, 'big') * num_padding

    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    # hexdump(packet)
    return packet

def send_udp_packets_v2(sport, client_iface, client_mac, client_ip, server_mac, server_ip, num_data):
    packet_list = []
    dports_list = construct_port_sequences(num_data + 1)
    for dports in dports_list:
        packet = construct_packet_with_metadata(sport, dports, client_iface, client_mac, client_ip, server_mac, server_ip, num_data)
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
    num_data = num_cores - 1

    client_iface = read_machine_info_from_file("client_iface")
    client_mac = read_machine_info_from_file("client_mac")
    client_ip = read_machine_info_from_file("client_ip")
    server_mac = read_machine_info_from_file("server_mac")
    server_ip = read_machine_info_from_file("server_ip")
    print(client_iface, client_mac, client_ip, server_mac, server_ip)
    if version == "v1":
        send_udp_packets_v1(sport, client_iface, client_mac, client_ip, server_mac, server_ip)
    elif version == "v2":
        send_udp_packets_v2(sport, client_iface, client_mac, client_ip, server_mac, server_ip, num_data)
