from scapy.all import *

PKTS_WRITE_MAX_NUM = 100000

def modify_pkt_size(pkt, pkt_len):
    payload_len = pkt_len - len(pkt)
    if payload_len <= 0:
        return pkt
    payload_data = b"X" * payload_len
    new_pkt = pkt / Raw(load=payload_data)
    return new_pkt
