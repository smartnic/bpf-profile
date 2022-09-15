# sudo python3 send_udp_packets_portknock_for_xl170.py [sport]

import argparse
from os.path import exists
from scapy.all import*
import sys

CONFIG_file_xl170 = "config.xl170"
DPORT_SEQ = [100, 101, 102]
PORT_TO_OPEN = 103

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

def construct_packet(sport, dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    seq = [100, 101, 102, 0x4567, 0x5678, 0x6789, 0x0123]
    dports_bytes = b''
    for p in seq:
        dports_bytes += p.to_bytes(2, 'big')

    payload=b'\x12\x34\x56\x78\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77'
    packet = Ether(src=client_mac,dst=server_mac)/IP(src=client_ip,dst=server_ip)/UDP(sport=sport,dport=dport)/Raw(load=dports_bytes)
    hexdump(packet)
    return packet

def send_udp_packets(dport, client_iface, client_mac, client_ip, server_mac, server_ip):
    packet = construct_packet(53, dport, client_iface, client_mac, client_ip, server_mac, server_ip)
    # packet_list = 100000 * packet_list
    # sendpfast(packet_list, iface=client_iface, pps=1000000, loop=100000000)
    sendpfast(packet, iface=client_iface)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please specify the destination port.")
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
