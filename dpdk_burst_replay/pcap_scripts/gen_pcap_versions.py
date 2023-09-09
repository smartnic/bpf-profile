import multiprocessing
import time
import argparse
import sys
import os
from read_args import read_args_from_yaml
from gen_pcap_shared_state import gen_pcap_shared_state
from gen_pcap_flow_affinity_hhd import gen_pcap_flow_affinity_hhd
from gen_pcap_with_md_hhd import gen_pcap_with_md_hhd
from gen_pcap_flow_affinity_ddos_mitigator import gen_pcap_flow_affinity_ddos_mitigator
from gen_pcap_with_md_ddos_mitigator import gen_pcap_with_md_ddos_mitigator
from gen_pcap_flow_affinity_token_bucket import gen_pcap_flow_affinity_token_bucket
from gen_pcap_with_md_token_bucket import gen_pcap_with_md_token_bucket
from process_pcap_file_ddos_srcip import read_src_ip_from_tcp_packets
from truncate_tcp_pkts_and_stats import truncate_tcp_pkts_and_stats

APPROACH_shared = "shared"
APPROACH_shared_nothing = "shared_nothing"
APPROACH_flow_affinity = "flow_affinity"

BM_hhd = "hhd"
BM_ddos_mitigator = "ddos_mitigator"
BM_token_bucket = "token_bucket"

def add_tasks_to_process_pool(approach, benchmarks, num_cores, dst_mac, output_path, input_file, tcp_only):
    sleep_dur = 0.1
    print(f"[add_tasks_to_process_pool] {approach} {benchmarks} {input_file} {tcp_only}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    result_list = []

    if BM_ddos_mitigator in benchmarks:
        r = pool.apply_async(read_src_ip_from_tcp_packets, args=(input_file, output_path, ))
        result_list.append(r)
        time.sleep(sleep_dur)

    if approach == APPROACH_shared:
        for n in range(1, num_cores + 1):
            r = pool.apply_async(gen_pcap_shared_state, args=(n, dst_mac, output_path, input_file, ))
            result_list.append(r)
            time.sleep(sleep_dur)
    elif approach == APPROACH_flow_affinity:
        for b in benchmarks:
            if b == BM_hhd:
                r = pool.apply_async(gen_pcap_flow_affinity_hhd,
                                     args=(dst_mac, output_path, input_file, ))
                result_list.append(r)
            elif b == BM_ddos_mitigator:
                dst_ip = "172.16.90.196"
                r = pool.apply_async(gen_pcap_flow_affinity_ddos_mitigator,
                                     args=(dst_mac, dst_ip, output_path, input_file, ))
                result_list.append(r)
            elif b == BM_token_bucket:
                r = pool.apply_async(gen_pcap_flow_affinity_token_bucket,
                                     args=(dst_mac, output_path, input_file, ))
                result_list.append(r)
            time.sleep(sleep_dur)
    elif approach == APPROACH_shared_nothing:
        for b in benchmarks:
            if b == BM_hhd:
                for n in range(1, num_cores + 1):
                    r = pool.apply_async(gen_pcap_with_md_hhd, args=(n, dst_mac, output_path, input_file, tcp_only, ))
                    result_list.append(r)
                    time.sleep(sleep_dur)
            elif b == BM_ddos_mitigator:
                for n in range(1, num_cores + 1):
                    r = pool.apply_async(gen_pcap_with_md_ddos_mitigator,
                                         args=(n, dst_mac, output_path, input_file, tcp_only, ))
                    result_list.append(r)
                    time.sleep(sleep_dur)
            elif b == BM_token_bucket:
                for n in range(1, num_cores + 1):
                    r = pool.apply_async(gen_pcap_with_md_token_bucket,
                                         args=(n, dst_mac, output_path, input_file, tcp_only, ))
                    result_list.append(r)
                    time.sleep(sleep_dur)
    return result_list

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--config', '-c', dest='config_file', help='Config file name', required=True)
    new_pcap_filename = "pkts.pcap"
    args = parser.parse_args()
    item_list = read_args_from_yaml(args.config_file)
    t_start = time.time()
    t_shared_state = time.time()
    n_processes = 27
    # create truncated packet traces and dump stats
    sleep_dur = 0.1
    with multiprocessing.Pool(processes=n_processes) as pool:
        result_list = []
        for item in item_list:
            input_file = item.input_file
            output_path = item.output
            output_filename = new_pcap_filename
            item.input_file = f"{output_path}/{output_filename}"
            max_pkt_len = item.max_pkt_len
            r = pool.apply_async(truncate_tcp_pkts_and_stats, 
                                 args=(input_file, output_path, output_filename, max_pkt_len, ))
            result_list.append(r)
            time.sleep(sleep_dur)
        # Wait for subprocesses to complete
        print(f"# of truncated and stats tasks: {len(result_list)}")
        c = 1
        for r in result_list:
            r.wait()
            print(f"truncated and stats task {c} completes")
            c += 1

    time.sleep(2)
    # Create n_processes multiprocessing Pools, one for each function
    with multiprocessing.Pool(processes=n_processes) as pool:
        result_list = []
        for item in item_list:
            input_file = item.input_file
            output_path = item.output
            tcp_only = item.tcp_only
            num_cores = item.num_cores
            dst_mac = item.dst_mac
            for approach, benchmarks in item.tasks.items():
                result_list += add_tasks_to_process_pool(approach, benchmarks, num_cores,
                                                         dst_mac, output_path, input_file,
                                                         tcp_only)

        # Wait for subprocesses to complete
        print(f"# of tasks: {len(result_list)}")
        c = 1
        for r in result_list:
            r.wait()
            print(f"task {c} completes")
            c += 1

    time_cost = time.time() - t_start
    print(f"time_cost: {time_cost}")
