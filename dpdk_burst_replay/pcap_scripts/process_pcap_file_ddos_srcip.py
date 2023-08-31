import argparse
from scapy.all import *
DDOS_SRCIP_FILE = "ddos_srcip.txt"

# Generator function to read and yield packets one by one
def read_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet_number, packet in enumerate(pcap_reader, start=0):
            yield packet_number, packet

# 1. ddos src ip list
def read_src_ip_from_tcp_packets(input_file, output_path):
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    src_ips = set()
    for i, packet in read_packets(input_file):
        if TCP in packet and IP in packet:
            src_ip = packet[IP].src
            src_ips.add(src_ip)
    output_file = f"{output_path}/{DDOS_SRCIP_FILE}"
    with open(output_file, "w") as file:
        for ip in src_ips:
            file.write(f"{ip}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output path", required=True)
    args = parser.parse_args()
    read_src_ip_from_tcp_packets(args.input_file, args.output_path)
