import multiprocessing
import time
import argparse
import sys
from gen_pcap_shared_state import gen_pcap_shared_state
from gen_pcap_flow_affinity_hhd import gen_pcap_flow_affinity_hhd
from gen_pcap_with_md_hhd import gen_pcap_with_md_hhd

APPROACH_shared = "shared"
APPROACH_shared_nothing = "shared_nothing"
APPROACH_flow_affinity = "flow_affinity"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--input', '-i', dest='input_file', help='Input file name', required=True)
    parser.add_argument("--output", "-o", dest="output_path", help="Output file name", required=True)
    parser.add_argument("--num_cores", "-n", dest="num_cores", help="Number of cores used to process packets", type=int, default=1)
    parser.add_argument("--dst_mac", "-d", dest="dst_mac", help="Destination MAC address to use in the generated PCAP file", default="00:00:00:00:00:02")
    parser.add_argument("--approaches", "-a", dest="approaches", help="Approaches: shared, shared_nothing, flow_affinity", default="shared,shared_nothing,flow_affinity")
    args = parser.parse_args()
    approaches = args.approaches.split(",")
    print(f"approaches: {approaches}")
    t_start = time.time()
    t_shared_state = time.time()
    n_processes = 27
    # if args.num_cores > n_processes:
    # Create n_processes multiprocessing Pools, one for each function
    with multiprocessing.Pool(processes=n_processes) as pool:
        result_list = []
        if APPROACH_shared in approaches:
            for n in range(1, args.num_cores + 1):
                r = pool.apply_async(gen_pcap_shared_state, args=(n, args.dst_mac, args.output_path, args.input_file, ))
                result_list.append(r)
        if APPROACH_flow_affinity in approaches:
            r = pool.apply_async(gen_pcap_flow_affinity_hhd, args=(args.dst_mac, args.output_path, args.input_file, ))
            result_list.append(r)
        if APPROACH_shared_nothing in approaches:
            for n in range(1, args.num_cores + 1):
                r = pool.apply_async(gen_pcap_with_md_hhd, args=(n, args.dst_mac, args.output_path, args.input_file, ))
                result_list.append(r)        
        # Wait for subprocesses to complete
        print(f"# of tasks: {len(result_list)}")
        c = 1
        for r in result_list:
            r.wait()
            print(f"task {c} completes")
            c += 1

    time_cost = time.time() - t_start
    print(f"time_cost: {time_cost}")
