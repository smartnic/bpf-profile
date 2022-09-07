# sudo python3 send_udp_packets_for_xl170.py [dport]

import argparse
from os.path import exists
from scapy.all import*
import sys

CONFIG_file_xl170 = "config.xl170"

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

def send_udp_packets(dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=53,dport=dport)/Raw("123456789012")
    packets = 100000 * packet
    sendpfast(packets, iface=client_iface, pps=1000000, loop=100000000)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please specify the destion port.")
        sys.exit(0)
    
    dport = int(sys.argv[1])
    print("dport = ", dport)

    client_iface = read_machine_info_from_file("client_iface")
    client_mac = read_machine_info_from_file("client_mac")
    client_ip = read_machine_info_from_file("client_ip")
    server_mac = read_machine_info_from_file("server_mac")
    server_ip = read_machine_info_from_file("server_ip")
    print(client_iface, client_mac, client_ip, server_mac, server_ip)
    send_udp_packets(dport, client_iface, client_mac, client_ip, server_mac, server_ip)