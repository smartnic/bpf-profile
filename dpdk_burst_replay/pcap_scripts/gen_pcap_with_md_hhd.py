import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
import os
from gen_pcap_utils import *

# from ctypes import *
# struct flow_key {
#   u8 protocol;
#   __be32 src_ip;
#   __be32 dst_ip;
#   u16 src_port;
#   u16 dst_port;
# } __attribute__((packed));

# struct metadata_elem {
#   __be16 ethtype;
#   struct flow_key flow;
#   u32 size;
#   bool tcp_fin_flag; /* if true: is a tcp fin packet */
# } __attribute__((packed));
class MetadataElem():
  def __init__(self):
    self.ethtype = 0
    self.protocol = 0
    self.src_ip = 0
    self.dst_ip = 0
    self.src_port = 0
    self.dst_port = 0
    self.size = 0
    self.tcp_fin_flag = False

  def __str__(self):
    str = f"Ethtype: {self.ethtype}\n"
    str += f"Proto: {self.protocol}\n"
    str += f"Source IP: {ipaddress.IPv4Address(self.src_ip)}\n"
    str += f"Dest IP: {ipaddress.IPv4Address(self.dst_ip)}\n"
    str += f"Source port: {self.src_port}\n"
    str += f"Dest port: {self.dst_port}\n"
    str += f"Size: {self.size}\n"
    str += f"tcp_fin_flag: {self.tcp_fin_flag}"
    return str

  def __bytes__(self):
    md_bytes = b''
    md_bytes += self.ethtype.to_bytes(2, 'big')
    md_bytes += self.protocol.to_bytes(1, 'big')
    md_bytes += self.src_ip.to_bytes(4, 'big')
    md_bytes += self.dst_ip.to_bytes(4, 'big')
    md_bytes += self.src_port.to_bytes(2, 'little')
    md_bytes += self.dst_port.to_bytes(2, 'little')
    md_bytes += self.size.to_bytes(4, 'little')
    md_bytes += self.tcp_fin_flag.to_bytes(1, 'little')
    return md_bytes


def get_md_from_pkt(pkt):
    md_elem = MetadataElem()
    # ETH_P_IP: 2048 (0x800)
    md_elem.ethtype = pkt.getlayer(Ether).type
    md_elem.src_ip = int(ipaddress.ip_address(pkt.getlayer(IP).src))
    md_elem.dst_ip = int(ipaddress.ip_address(pkt.getlayer(IP).dst))
    if pkt.haslayer(TCP):
        md_elem.protocol = socket.IPPROTO_TCP
        md_elem.src_port = pkt.getlayer(TCP).sport
        md_elem.dst_port = pkt.getlayer(TCP).dport
        md_elem.tcp_fin_flag = pkt.getlayer(TCP).flags.F
    elif pkt.haslayer(UDP):
        md_elem.protocol = socket.IPPROTO_UDP
        md_elem.src_port = pkt.getlayer(UDP).sport
        md_elem.dst_port = pkt.getlayer(UDP).dport
    else:
        print(f"Unsupported layer type: {pkt.getlayer(IP).proto}")
        sys.exit(1)
    md_elem.size = len(pkt)
    # print(md_elem)
    return md_elem

# Generator function to read and yield packets one by one
def read_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet_number, packet in enumerate(pcap_reader, start=1):
            yield packet_number, packet

def gen_pcap_with_md_hhd(num_cores, dst_mac, output_path, input_file):
    print(f"start [gen_pcap_with_md_hhd] num_cores: {num_cores}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    output_file = f"{output_path}/xdp_hhd_shared_nothing_{num_cores}.pcap"
    # input_pkts = rdpcap(input_file)
    new_pkts = list()
    md_initial = MetadataElem()
    pkt_history = []
    if num_cores > 1:
        pkt_history = [md_initial] * (num_cores - 1)
    for i, curr_pkt in read_packets(input_file):
        # print(f"\npkt {i}....")
        # get metadata from curr_pkt
        md_bytes = b''
        for x in pkt_history:
            md_bytes += bytes(x)
        # src_mac is used for rss
        src_mac = f"10:10:10:10:10:{format(i % num_cores, '02x')}"
        # print(src_mac)
        new_pkt = Ether(dst = dst_mac, src = src_mac, type=ETH_P_IP) / \
                  md_bytes / \
                  curr_pkt
        new_pkts.append(new_pkt)
        if num_cores > 1:
            curr_md = get_md_from_pkt(curr_pkt)
            # update pkt_history
            pkt_history = pkt_history[1:]
            pkt_history.append(curr_md)
        if len(new_pkts) >= PKTS_WRITE_SIZE:
            wrpcap(output_file, new_pkts, append=True)
            # print(f"Written {len(new_pkts)} packets to {output_pcap}")
            new_pkts = []
    if new_pkts:
        wrpcap(output_file, new_pkts, append=True)
    print(f"[gen_pcap_with_md_hhd] output pcap: {output_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output file name", required=True)
    parser.add_argument("--num_cores", "-n", dest="num_cores", help="Number of cores used to process packets", type=int, default=1)
    parser.add_argument("--dst_mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")
    args = parser.parse_args()
    dst_mac = args.dst_mac
    gen_pcap_with_md_hhd(args.num_cores, dst_mac, args.output_path, args.input_file)

