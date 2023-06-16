import socket
import ipaddress
from scapy.all import *
from scapy.utils import wrpcap

def modify_mac_one_pkt(curr_pkt, src_mac, dst_mac):
    new_pkt = Ether(dst = dst_mac, src = src_mac, type=ETH_P_IP)/ \
              curr_pkt[Ether].payload
    return new_pkt

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
    src_mac = "10:70:fd:d6:a0:1c"
    input_file = "trace_10_mtu1500/trace_10_mtu1500.pcap"
    input_pkts = rdpcap(input_file)
    print(f'{len(input_pkts)} packets in this pcap')
    new_pkts = modify_mac(input_pkts, src_mac, dst_mac)
    # new_pkts = add_padding(new_pkts)
    # sendp(new_pkts, iface="ens114np0")
    output_file = f"trace_10_mtu1500/xdp_hhd_flow_affinity.pcap"
    wrpcap(output_file, new_pkts)
