import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap

ETH_BYTES = 14

# struct st_k {
#   uint32_t src_ip;
#   uint32_t dst_ip;
#   uint16_t src_port;
#   uint16_t dst_port;
#   uint8_t proto;
# } __attribute__((packed));

# struct metadata_elem {
#   __be16 ethtype;
#   struct st_k flow;
#   bool tcp_fin_flag; /* if true: is a tcp fin packet */
# } __attribute__((packed));
class MetadataElem():
  def __init__(self):
    self.ethtype = 0
    self.src_ip = 0
    self.dst_ip = 0
    self.src_port = 0
    self.dst_port = 0
    self.protocol = 0
    self.tcp_fin_flag = False

  def __str__(self):
    str = f"Ethtype: {self.ethtype}\n"
    str += f"Source IP: {ipaddress.IPv4Address(self.src_ip)}\n"
    str += f"Dest IP: {ipaddress.IPv4Address(self.dst_ip)}\n"
    str += f"Source port: {self.src_port}\n"
    str += f"Dest port: {self.dst_port}\n"
    str += f"Proto: {self.protocol}\n"
    str += f"tcp_fin_flag: {self.tcp_fin_flag}"
    return str

  def __bytes__(self):
    md_bytes = b''
    md_bytes += self.ethtype.to_bytes(2, 'big')
    md_bytes += self.src_ip.to_bytes(4, 'big')
    md_bytes += self.dst_ip.to_bytes(4, 'big')
    md_bytes += self.src_port.to_bytes(2, 'little')
    md_bytes += self.dst_port.to_bytes(2, 'little')
    md_bytes += self.protocol.to_bytes(1, 'big')
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
    # print(md_elem)
    return md_elem

def add_md_to_pkts(input_pkts, num_cores, dst_mac, padding_size):
    new_pkts = list()
    md_initial = MetadataElem()
    pkt_history = []
    if num_cores > 1:
        pkt_history = [md_initial] * (num_cores - 1)
    padding_to_add = padding_size - len(bytes(md_initial)) * (num_cores - 1)
    padding_to_add -= ETH_BYTES
    print(f"padding_to_add: {padding_to_add} bytes")
    for i, curr_pkt in enumerate(input_pkts):
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
        if padding_to_add > 0:
            zero = 0
            padding = zero.to_bytes(padding_to_add, 'little')
            new_pkt = new_pkt / padding
        new_pkts.append(new_pkt)
        if num_cores > 1:
            curr_md = get_md_from_pkt(curr_pkt)
            # update pkt_history
            pkt_history = pkt_history[1:]
            pkt_history.append(curr_md)
    return new_pkts

if __name__ == '__main__':
    md_elem_bytes = 20 * 10
    padding_size = ETH_BYTES + md_elem_bytes
    print(f"padding_size: {padding_size} bytes")
    num_cores_max = 11
    num_cores_min = 1
    dst_mac = "10:70:fd:d6:a0:64"
    # src_mac = "10:70:fd:d6:a0:1c"
    input_file = "trace_10.pcap"
    input_pkts = rdpcap(input_file)
    print(f'{len(input_pkts)} packets in this pcap')
    for n in range(num_cores_min, num_cores_max + 1):
        print(f"processing {n}")
        new_pkts = add_md_to_pkts(input_pkts, n, dst_mac, padding_size)
        output_file = f"trace_10_nat_dp_shared_nothing.pcap.{n}"
        print(f"output pcap: {output_file}")
        wrpcap(output_file, new_pkts)
