import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap
import argparse
import os
from gen_pcap_utils import *

TCP_ONLY = False

# struct flow_key {
#     __u32 src_ip;
#     __u32 dst_ip;
#     __u16 src_port;
#     __u16 dst_port;
#     __u8 protocol;
# } __attribute__((packed));

# struct flow_info {
#     __u8 flags;
#     __u32 seq_num;
#     __u32 ack_num;
#     __u64 timestamp;
# } __attribute__((packed));

# struct metadata_elem {
#     struct flow_key flow;
#     struct flow_info info;
# } __attribute__((packed));
class MetadataElem():
  def __init__(self):
    self.src_ip = 0
    self.dst_ip = 0
    self.src_port = 0
    self.dst_port = 0
    self.protocol = 0
    self.tcp_flags = ""
    self.seq_num = 0
    self.ack_num = 0
    self.timestamp = 0

  def __str__(self):
    str += f"Proto: {self.protocol}\n"
    str += f"Source IP: {ipaddress.IPv4Address(self.src_ip)}\n"
    str += f"Dest IP: {ipaddress.IPv4Address(self.dst_ip)}\n"
    str += f"Source port: {self.src_port}\n"
    str += f"Dest port: {self.dst_port}\n"
    str += f"tcp_flags: {self.tcp_flags}\n"
    str += f"seq_num: {self.seq_num}\n"
    str += f"ack_num: {self.ack_num}\n"
    str += f"timestamp: {self.timestamp}\n"
    return str

  def get_tcp_flags_byte(self):
    tcp_flags_str = self.tcp_flags
    tcp_flags_byte = 0
    # Set each bit in the byte based on the TCP flags
    if 'U' in tcp_flags_str:
        tcp_flags_byte |= 1 << 0  # Urgent bit (position 0)
    if 'A' in tcp_flags_str:
        tcp_flags_byte |= 1 << 4  # Acknowledgment bit (position 4)
    if 'P' in tcp_flags_str:
        tcp_flags_byte |= 1 << 3  # Push bit (position 3)
    if 'R' in tcp_flags_str:
        tcp_flags_byte |= 1 << 2  # Reset bit (position 2)
    if 'S' in tcp_flags_str:
        tcp_flags_byte |= 1 << 1  # Syn bit (position 1)
    if 'F' in tcp_flags_str:
        tcp_flags_byte |= 1 << 0  # Fin bit (position 0)
    return int(tcp_flags_byte)

  def __bytes__(self):
    md_bytes = b''
    md_bytes += self.src_ip.to_bytes(4, 'big')
    md_bytes += self.dst_ip.to_bytes(4, 'big')
    md_bytes += self.src_port.to_bytes(2, 'big')
    md_bytes += self.dst_port.to_bytes(2, 'big')
    md_bytes += self.protocol.to_bytes(1, 'big')
    md_bytes += self.get_tcp_flags_byte().to_bytes(1, 'big')
    md_bytes += self.seq_num.to_bytes(4, 'big')
    md_bytes += self.ack_num.to_bytes(4, 'big')
    md_bytes += int(self.timestamp).to_bytes(8, 'big')
    return md_bytes


def get_md_from_pkt(pkt):
    md_elem = MetadataElem()
    # ETH_P_IP: 2048 (0x800)
    md_elem.src_ip = int(ipaddress.ip_address(pkt.getlayer(IP).src))
    md_elem.dst_ip = int(ipaddress.ip_address(pkt.getlayer(IP).dst))
    if pkt.haslayer(TCP):
        md_elem.protocol = socket.IPPROTO_TCP
        md_elem.src_port = pkt.getlayer(TCP).sport
        md_elem.dst_port = pkt.getlayer(TCP).dport
        md_elem.tcp_flags = pkt.getlayer(TCP).flags
        md_elem.seq_num = pkt.getlayer(TCP).seq
        md_elem.ack_num = pkt.getlayer(TCP).ack
        md_elem.timestamp = pkt.time
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
        for packet_number, packet in enumerate(pcap_reader, start=0):
            yield packet_number, packet

def gen_pcap_with_md_conntrack(num_cores, dst_mac, output_path, input_file, tcp_only, pkt_len):
    global TCP_ONLY
    TCP_ONLY = tcp_only
    print(f"start [gen_pcap_with_md_conntrack] num_cores: {num_cores}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    output_file = f"{output_path}/xdp_conntrack_shared_nothing_{num_cores}.pcap"
    append_flag = False
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
        new_pkt = modify_pkt_size(new_pkt, pkt_len)
        new_pkts.append(new_pkt)
        if num_cores > 1:
            curr_md = get_md_from_pkt(curr_pkt)
            # update pkt_history
            pkt_history = pkt_history[1:]
            pkt_history.append(curr_md)
        if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
            wrpcap(output_file, new_pkts, append=append_flag)
            # print(f"Written {len(new_pkts)} packets to {output_pcap}")
            new_pkts = []
            append_flag = True
    if new_pkts:
        wrpcap(output_file, new_pkts, append=append_flag)
    print(f"[gen_pcap_with_md_conntrack] output pcap: {output_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output file name", required=True)
    parser.add_argument("--num_cores", "-n", dest="num_cores", help="Number of cores used to process packets", type=int, default=1)
    parser.add_argument("--dst_mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")
    parser.add_argument('--tcp_only', dest='tcp_only', help='Only TCP packets', action='store_true', required=False)
    parser.add_argument("--pkt_len", dest="pkt_len", help="Pkt len", type=int, default=64)
    args = parser.parse_args()
    dst_mac = args.dst_mac
    gen_pcap_with_md_conntrack(args.num_cores, dst_mac, args.output_path, args.input_file, args.tcp_only, args.pkt_len)

