import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap

def modify_mac_one_pkt(curr_pkt, src_mac, dst_mac):
    new_pkt = Ether(dst = dst_mac, src = src_mac, type=ETH_P_IP)/ \
              curr_pkt[Ether].payload
    return new_pkt

def support_rss_pkts(input_pkts, num_cores, dst_mac):
    new_pkts = list()
    num_padding_elem = 11 - num_cores
    print(f"num_padding_elem: {num_padding_elem}")
    for i, curr_pkt in enumerate(input_pkts):
        # print(f"\npkt {i}....")
        # src_mac is used for rss
        src_mac = f"10:10:10:10:10:{format(i % num_cores, '02x')}"
        # print(src_mac)
        new_pkt = modify_mac_one_pkt(curr_pkt, src_mac, dst_mac)
        new_pkts.append(new_pkt)
    return new_pkts

def modify_mac(input_pkts, src_mac, dst_mac):
    new_pkts = []
    for pkt in input_pkts:
        new_pkts.append(modify_mac_one_pkt(pkt, src_mac, dst_mac))
    return new_pkts

def add_padding(input_pkts):
    eth_bytes = 14
    md_elem_bytes = 20 * 10
    total_bytes = eth_bytes + md_elem_bytes
    new_pkts = []
    payload = 'x' * total_bytes
    for pkt in input_pkts:
        pkt /= Raw(load=payload)
        new_pkts.append(pkt)
    return new_pkts


if __name__ == '__main__':
    num_cores_max = 9
    num_cores_min = 1
    dst_mac = "10:70:fd:d6:a0:64"
    # src_mac = "10:70:fd:d6:a0:1c"
    input_file = "trace_10_mtu1500/trace_10_mtu1500.pcap"
    input_pkts = rdpcap(input_file)
    print(f'{len(input_pkts)} packets in this pcap')
    for n in range(num_cores_min, num_cores_max + 1):
        print(f"processing {n}")
        new_pkts = support_rss_pkts(input_pkts, n, dst_mac)
        # new_pkts = add_padding(new_pkts)
        # sendp(new_pkts, iface="ens114np0")
        output_file = f"trace_10_mtu1500/shared_state_{n}.pcap"
        wrpcap(output_file, new_pkts)
