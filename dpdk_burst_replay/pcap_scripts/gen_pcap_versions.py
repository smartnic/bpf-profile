import multiprocessing
import time
import argparse
import sys
from read_args import read_args_from_yaml
from gen_pcap_shared_state import gen_pcap_shared_state
from gen_pcap_flow_affinity_hhd import gen_pcap_flow_affinity_hhd
from gen_pcap_with_md_hhd import gen_pcap_with_md_hhd
from gen_pcap_flow_affinity_ddos_mitigator import gen_pcap_flow_affinity_ddos_mitigator
from gen_pcap_with_md_ddos_mitigator import gen_pcap_with_md_ddos_mitigator

APPROACH_shared = "shared"
APPROACH_shared_nothing = "shared_nothing"
APPROACH_flow_affinity = "flow_affinity"

BM_hhd = "hhd"
BM_ddos_mitigator = "ddos_mitigator"

def add_tasks_to_process_pool(approach, benchmarks, num_cores, dst_mac, output_path, input_file):
    print(f"[add_tasks_to_process_pool] {approach} {benchmarks} {input_file}")
    result_list = []
    if approach == APPROACH_shared:
        for n in range(1, num_cores + 1):
            r = pool.apply_async(gen_pcap_shared_state, args=(n, dst_mac, output_path, input_file, ))
            result_list.append(r)
    elif approach == APPROACH_flow_affinity:
        for b in benchmarks:
            if b == BM_hhd:
                r = pool.apply_async(gen_pcap_flow_affinity_hhd,
                                     args=(dst_mac, output_path, input_file, ))
                result_list.append(r)
            if b == BM_ddos_mitigator:
                dst_ip = "172.16.90.196"
                r = pool.apply_async(gen_pcap_flow_affinity_ddos_mitigator,
                                     args=(dst_mac, dst_ip, output_path, input_file, ))
                result_list.append(r)
    elif approach == APPROACH_shared_nothing:
        for b in benchmarks:
            if b == BM_hhd:
                for n in range(1, num_cores + 1):
                    r = pool.apply_async(gen_pcap_with_md_hhd, args=(n, dst_mac, output_path, input_file, ))
                    result_list.append(r)
            elif b == BM_ddos_mitigator:
                for n in range(1, num_cores + 1):
                    r = pool.apply_async(gen_pcap_with_md_ddos_mitigator,
                                         args=(n, dst_mac, output_path, input_file, ))
                    result_list.append(r)
    return result_list

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--config', '-c', dest='config_file', help='Config file name', required=True)
    args = parser.parse_args()
    item_list = read_args_from_yaml(args.config_file)
    t_start = time.time()
    t_shared_state = time.time()
    n_processes = 27
    # if args.num_cores > n_processes:
    # Create n_processes multiprocessing Pools, one for each function
    with multiprocessing.Pool(processes=n_processes) as pool:
        result_list = []
        for item in item_list:
            input_file = item.input_file
            output_path = item.output
            num_cores = item.num_cores
            dst_mac = item.dst_mac
            for approach, benchmarks in item.tasks.items():
                result_list += add_tasks_to_process_pool(approach, benchmarks, num_cores,
                                                         dst_mac, output_path, input_file)

        # Wait for subprocesses to complete
        print(f"# of tasks: {len(result_list)}")
        c = 1
        for r in result_list:
            r.wait()
            print(f"task {c} completes")
            c += 1

    time_cost = time.time() - t_start
    print(f"time_cost: {time_cost}")
