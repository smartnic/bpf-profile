# sudo python3 send_udp_packets_test.py [sport]

import argparse
from os.path import exists
from scapy.all import*
import sys

CONFIG_file_xl170 = "config.xl170"
DPORT_SEQ = [100, 101, 102]
PORT_START = 1
PORT_ALLOW = 5555

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
def construct_packet_sequences():
    res = []
    port = PORT_START
    port_allow = PORT_ALLOW
    dports_list = dport_permutation(len(DPORT_SEQ))
    for dports in dports_list:
        # if the knocking sequence is correct, set the port as PORT_ALLOW
        if dports == DPORT_SEQ:
            res.append(dports + [port_allow]) # knocking sequence + port_allow
        else:
            res.append(dports + [port]) # knocking sequence + port
            port += 1
    print("packet sequences:")
    for x in res:
        print(x)
    return res;

def construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    payload=b'\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77'
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=payload)
    # hexdump(packet)
    return packet

def send_udp_packets(sport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packet_list = []
    dports_list = construct_packet_sequences()
    for dports in dports_list:
        for dport in dports:
            packet = construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
            packet_list.append(packet)
    sendpfast(packet_list, iface=client_iface)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please specify the source port.")
        sys.exit(0)
    
    sport = int(sys.argv[1])
    print("sport = ", sport)

    client_iface = read_machine_info_from_file("client_iface")
    client_mac = read_machine_info_from_file("client_mac")
    client_ip = read_machine_info_from_file("client_ip")
    server_mac = read_machine_info_from_file("server_mac")
    server_ip = read_machine_info_from_file("server_ip")
    print(client_iface, client_mac, client_ip, server_mac, server_ip)
    send_udp_packets(sport, client_iface, client_mac, client_ip, server_mac, server_ip)
