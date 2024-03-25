from scapy.all import *
from scapy.utils import wrpcap
import argparse
import os
from gen_pcap_utils import *
import random

# uniformly sample unique (no repetitive) `num_samples` numbers in [start, stop]
# excluding numbers in `excluded_numbers`
def sample(start, stop, num_samples, excluded_numbers):
    random.seed(42)
    # Exclude `excluded_numbers`
    valid_numbers = [num for num in range(start, stop + 1, 1) if num not in excluded_numbers]
    # Sample from the range
    samples = random.sample(valid_numbers, num_samples)
    sorted_samples = sorted(samples)
    # Print the sampled values
    print("Sampled values:", sorted_samples)
    return sorted_samples

def sample_test():
    loss_rate = 0.02
    excluded_numbers = [1, 2, 6]
    num_pkts = 10000
    num_samples = round(loss_rate * num_pkts)
    sample(0, num_pkts-1, num_samples, excluded_numbers)

# Generator function to read and yield packets one by one
def read_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        # packet_number starts from 0
        for packet_number, packet in enumerate(pcap_reader, start=0):
            yield packet_number, packet

def count_packets_get_excluded_ids(input_file):
    count = 0
    excluded_ids = []
    for i, pkt in read_packets(input_file):
        count += 1
    print(f"{count} packets in {input_file}")
    print(f"{len(excluded_ids)} excluded ids")
    return count, excluded_ids

# Packets we cannot remove:
# 1. last x packets (In experiments, we need to replay the trace. 
#    After resetting the metadata log for the first packet at core c, other cores
#    cannot get metadata info of last x packets from core c)
def remove_packets(input_file, output_file, num_first_pkts_left, num_last_pkts_left, loss_rate):
    num_pkts, excluded_ids = count_packets_get_excluded_ids(input_file)
    min_sample_id = num_first_pkts_left
    max_sample_id = num_pkts - num_last_pkts_left - 1
    if max_sample_id < min_sample_id:
        return
    num_samples = round(loss_rate * num_pkts)
    sorted_samples = sample(min_sample_id, max_sample_id, num_samples, excluded_ids)
    sample_output_file = f"{output_file}.sample.txt"
    with open(sample_output_file, 'w') as file:
        file.write(f"Loss_rate: {loss_rate}, number of pkts: {num_pkts}, number of samples: {num_samples}, ")
        file.write(f"num_last_pkts_left: {num_last_pkts_left}\n")
        file.write(f"Sampled values: {sorted_samples}\n")
    samples = set(sorted_samples)
    append_flag = False
    new_pkts = list()
    count = 0
    for idx, pkt in read_packets(input_file):
        if idx not in samples:
            new_pkts.append(pkt)
            if len(new_pkts) >= PKTS_WRITE_MAX_NUM:
                wrpcap(output_file, new_pkts, append=append_flag)
                new_pkts = []
                append_flag = True
                count += PKTS_WRITE_MAX_NUM
    if new_pkts:
        wrpcap(output_file, new_pkts, append=append_flag)
        count += len(new_pkts)
    print(f"After removing, {count} packets in {output_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_file", help="Output file name", required=True)
    args = parser.parse_args()
    loss_rate = 0.01
    # output_file = "xdp_portknock_shared_nothing_pkt_loss_4.pkt_removed.pcap"
    num_first_pkts_left = 1024
    num_last_pkts_left = num_first_pkts_left
    remove_packets(args.input_file, args.output_file, num_first_pkts_left, num_last_pkts_left, loss_rate)
