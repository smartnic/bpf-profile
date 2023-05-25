import argparse
from os.path import exists
import subprocess
import os
import sys
import time
from os.path import expanduser
from client import send_command
from socket_commands import *

CLIENT_DIR = ""
CONFIG_file_xl170 = "config.xl170"
LOADER_NAME = ""
CLIENT=""
SERVER_IFACE = ""
MAX_RX_QUEUES = 32

DISABLE_prog_latency = False
DISABLE_prog_latency_ns = False
DISABLE_insn_latency = False
DISABLE_pcm = False
DISABLE_pktgen_measure = False
DISABLE_pktgen_measure_parallel = False
BENCHMARK_portknock = "portknock"
BENCHMARK_hhd = "hhd"
BENCHMARK_ddos_mitigator = "ddos_mitigator"
BENCHMARK_token_bucket = "token_bucket"
BENCHMARK_nat_dp = "nat_dp"
BENCHMARK_xdpex1 = "xdpex1"

CPU_ARM = "arm"
CPU_INTEL = "intel"
CPU_AMD = "amd"

PKTGEN_PATH = None

def get_prog_tag():
    cmd = "bpftool prog show | grep xdp"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
    except:
        print ("ERROR: no xdp found! not able to get program tag")
        raise
        return
    tag = output.split()[5]
    print(f"program tag is {tag}")
    return tag

def run_cmd(cmd, wait=True):
    print(cmd)
    if wait is True:
        process = subprocess.Popen(cmd, shell=True, close_fds=True)
        process.wait()
    else:
        os.system(cmd)
        # subprocess.run(cmd.split(), shell=True)

# run a command
# para cmd: the command to run. type: string
def run_cmd_on_core(cmd, core_id):
    cmd = f"nohup sudo -b taskset -c {str(core_id)} {cmd} >/dev/null 2>&1 &"
    run_cmd(cmd, wait=False)

def run_cmd_on_client(client_cmd, client):
    # cmd = f"ssh -p 22 {client} \"nohup sudo sh -c '{client_cmd}'\""
    # run_cmd(cmd)
    cmd = f"nohup sudo sh -c '{client_cmd}'"
    res = send_command(cmd)
    print(f"run_cmd_on_client: {res}")
    return res

def run_unmodified_cmd_on_client(client_cmd, client):
    res = send_command(client_cmd)
    print(f"run_cmd_on_client: {res}")
    return res

def kill_process_on_client(process, client):
    client_cmd = f"pkill -f {process} >/dev/null 2>&1 &"
    run_cmd_on_client(client_cmd, client)

def clean_environment(client, prog_name):
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    # stop packet generation
    kill_process_on_client("dpdk-replay", client)
    kill_process_on_client("measure.py", client)
    loader_cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd(f"pkill -f \"{loader_cmd}\"", wait=True)

def run_packet_generator(benchmark, version, core_list, pcap_file, client):
    # send packets for 10000 seconds
    NIC_PCIE = "0000:ca:00.0"
    client_cmd = f"sudo {PKTGEN_PATH}/dpdk-replay --nbruns 100000000 --numacore 1 --timeout 10000 --stats {NIC_PCIE} {pcap_file} {NIC_PCIE} >log.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)
    # check if packet gen is stable
    client_cmd = CMD_CHECK_PKT_GEN_STABLE
    res = run_unmodified_cmd_on_client(client_cmd, client)
    time.sleep(5)

def pktgen_measure(client, output_path, dur):
    client_cmd = f"python3 {PKTGEN_PATH}measure.py -o {output_path} -t {dur} >log_pktgen_measure.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)
    time.sleep(dur + 1)

def get_benchmark_version(prog_name):
    benchmark = None
    version = None
    if BENCHMARK_portknock in prog_name:
        benchmark = BENCHMARK_portknock
    elif BENCHMARK_hhd in prog_name:
        benchmark = BENCHMARK_hhd
    elif BENCHMARK_ddos_mitigator in prog_name:
        benchmark = BENCHMARK_ddos_mitigator
    elif BENCHMARK_token_bucket in prog_name:
        benchmark = BENCHMARK_token_bucket
    elif BENCHMARK_nat_dp in prog_name:
        benchmark = BENCHMARK_nat_dp
    else:
        benchmark = BENCHMARK_xdpex1
    versions = ["v10", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"]
    for v in versions:
        if v in prog_name:
            version = v
            break
    return benchmark, version


def set_up_configs(benchmark, version, n_cores):
    is_flow_affinity = False
    flow_affinity_version_dic = {
        BENCHMARK_hhd: "v2",
    }
    hash_packet_fields_dic = {
        BENCHMARK_hhd: "sdfn",
    }
    print(f"benchmark: {benchmark}")
    if benchmark not in flow_affinity_version_dic:
        print(f"Benchmark {benchmark} not supported. Exit")
        sys.exit(0)
    if benchmark not in hash_packet_fields_dic:
        print(f"Benchmark {benchmark} not supported. Exit")
        sys.exit(0)
    flow_affinity_version = flow_affinity_version_dic[benchmark]
    hash_packet_fields = hash_packet_fields_dic[benchmark]
    if flow_affinity_version == version:
        is_flow_affinity = True
    print(f"is_flow_affinity: {is_flow_affinity}")
    print(f"hash_packet_fields: {hash_packet_fields}")

    if is_flow_affinity:
        # 1. delete RSS rules (delete all possible rules)
        run_cmd(f"bash rss_delete.sh {SERVER_IFACE} 0 1023")
        # 2. set up # of rx queues
        run_cmd(f"ethtool -L {SERVER_IFACE} combined {n_cores}")
        # 3. set up packet fields for hash function
        run_cmd(f"ethtool -N {SERVER_IFACE} rx-flow-hash tcp4 {hash_packet_fields}")
    else:
        # 1. delete RSS rules (delete all possible rules)
        run_cmd(f"bash rss_delete.sh {SERVER_IFACE} 0 1023")
        # 2. set up # of rx queues (actually we can enable all queues)
        run_cmd(f"ethtool -L {SERVER_IFACE} combined {MAX_RX_QUEUES}")
        # 3. add RSS rules
        run_cmd(f"bash rss.sh {SERVER_IFACE}")


    print(f"Display configurations: {benchmark}, {version}, {n_cores}")
    run_cmd(f"ethtool --show-nfc {SERVER_IFACE}")
    run_cmd(f"ethtool -l {SERVER_IFACE}")
    run_cmd(f"ethtool -n {SERVER_IFACE} rx-flow-hash tcp4")


def run_test(prog_name, core_list, client, seconds, output_folder, output_folder_pktgen):
    benchmark, version = get_benchmark_version(prog_name)
    # 1. print test name and environment configurations such as RSS
    print("Test",  prog_name, "across", len(core_list), "core(s) for", str(seconds), "seconds...")
    set_up_configs(benchmark, version, len(core_list))
    return

    # 2. attach xdp program
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd_on_core(cmd, 0)

    # 3. run packet generator
    n_cores = len(core_list)
    pcap_file = f"/data/local/qx51/bpf-profile/profile/pkt_trace/trace_10.pcap.{n_cores}"
    run_packet_generator(benchmark, version, core_list, pcap_file, client)

    # 4. measure the xdp prorgam
    try:
        tag = get_prog_tag()
    except:
        print(f"ERROR: not able to get the tag of {prog_name}. Test stop...")
        clean_environment(client, prog_name)
        return

    # 4.5 run performance measurement on the packet generator
    if not DISABLE_pktgen_measure:
        pktgen_measure(client, f"{output_folder_pktgen}/no_profile/", seconds)
        time.sleep(5)

    # 5. clean environment
    clean_environment(client, prog_name)
    time.sleep(5)

def run_tests_versions(prog_name_prefix, core_num_max, duration,
                       output_folder, output_folder_pktgen, run_id):
    if DISABLE_prog_latency and DISABLE_prog_latency_ns and DISABLE_insn_latency and DISABLE_pcm and DISABLE_pktgen_measure:
        return
    core_list = []
    for i in range(1, core_num_max + 1):
        core_list.append(i)
        prog_name = f"{prog_name_prefix}_p{i}"
        output_folder_i = output_folder + "/" + str(i) + "/" + str(run_id)
        run_cmd("sudo mkdir -p " + output_folder_i, wait=True)
        output_folder_i_pktgen = output_folder_pktgen + "/" + str(i) + "/" + str(run_id)
        run_test(prog_name, core_list, CLIENT, duration, output_folder_i,
            output_folder_i_pktgen)

def read_machine_info_from_file(input_file):
    client = None
    server_iface = None
    client_dir = None
    client_keyword = "client"
    server_iface_keyword = "server_iface"
    client_dir_keyword = "client_dir"
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return client: None, server_iface: None, client_dir: None")
        return None, None, None
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(":", 1) # split on first occurrence
        if len(line) < 2:
            continue
        if line[0] == client_keyword:
            client = line[1].strip()
        elif line[0] == server_iface_keyword:
            server_iface = line[1].strip()
        elif line[0] == client_dir_keyword:
            client_dir = line[1].strip()
    f.close()
    return client, server_iface, client_dir

def test_benchmark(run_id, benchmark, version_name_list,
    num_cores_max, duration, output_folder, output_folder_pktgen):
    print(f"Benchmark {benchmark} run {run_id} starts......")
    t_start = time.time()
    for version in version_name_list:
        t_start_v = time.time()
        prog_name_prefix = f"{benchmark}_{version}"
        output_folder_version_dut = f"{output_folder}/{version}"
        output_folder_version_pktgen = f"{output_folder_pktgen}/{version}"
        run_tests_versions(prog_name_prefix, num_cores_max, duration,
            output_folder_version_dut, output_folder_version_pktgen, run_id)
        time_cost_v = time.time() - t_start_v
        print(f"Run {run_id} {version} test ends. time_cost: {time_cost_v}")
    time_cost = time.time() - t_start
    print(f"Benchmark {benchmark} run {run_id} ends. time_cost: {time_cost}")

# add pcap file
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-o', dest="output_folder", type=str, help='Output path on DUT', required=True)
    parser.add_argument('--o_pktgen', dest="output_folder_pktgen", type=str, default=None, help='Output path on the packet generator, default is the same as output path on DUT', required=False)
    parser.add_argument('-b', dest="benchmark_list", type=str, default="all", help='XDP benchmark list, e.g., xdp_portknock,xdp_hhd. `all` means all benchmarks', required=False)
    parser.add_argument('-r', dest="num_runs", type=int, help='Total number of runs (greater than 1)', required=True)
    parser.add_argument('--nc_max', dest="num_cores_max", type=int, help='Maximum number of cores (greater than 1)', required=True)
    parser.add_argument('-d', dest="duration", type=int, help='Duration for each test. Unit: seconds', required=True)
    parser.add_argument('--disable_prog_latency', action='store_true', help='Disable prog latency measurement', required=False)
    parser.add_argument('--disable_prog_latency_ns', action='store_true', help='Disable prog latency (nanoseconds, use kernel stats) measurement', required=False)
    parser.add_argument('--disable_insn_latency', action='store_true', help='Disable insn latency measurement', required=False)
    parser.add_argument('--disable_pcm', action='store_true', help='Disable pcm measurement', required=False)
    parser.add_argument('--disable_pktgen_measure_parallel', action='store_true', help='Disable pktgen measurement while measuring other metrics: round-trip latency and throughput', required=False)
    parser.add_argument('--disable_pktgen_measure', action='store_true', help='Disable pktgen measurement: round-trip latency and throughput', required=False)
    args = parser.parse_args()
    if args.output_folder_pktgen is None:
        args.output_folder_pktgen = args.output_folder
    if args.benchmark_list == "all":
        benchmark_list = [f"xdp_{BENCHMARK_portknock}", f"xdp_{BENCHMARK_hhd}",
                          f"xdp_{BENCHMARK_token_bucket}", f"xdp_{BENCHMARK_ddos_mitigator}",
                          f"xdp_{BENCHMARK_nat_dp}"]
    else:
        benchmark_list = args.benchmark_list.split(",")
    DISABLE_prog_latency = args.disable_prog_latency
    DISABLE_prog_latency_ns = args.disable_prog_latency_ns
    DISABLE_insn_latency = args.disable_insn_latency
    DISABLE_pcm = args.disable_pcm
    DISABLE_pktgen_measure_parallel = args.disable_pktgen_measure_parallel
    DISABLE_pktgen_measure = args.disable_pktgen_measure
    if DISABLE_prog_latency and DISABLE_prog_latency_ns and DISABLE_insn_latency and DISABLE_pcm and DISABLE_pktgen_measure and DISABLE_mlffr:
        sys.exit(0)
    # read client and server_iface from config.xl170
    CLIENT, SERVER_IFACE, CLIENT_DIR = read_machine_info_from_file(CONFIG_file_xl170)
    if CLIENT is None or SERVER_IFACE is None or CLIENT_DIR is None:
        sys.exit(0)

    PKTGEN_PATH = f"{CLIENT_DIR}/dpdk-burst-replay/src/"
    t_start_experiments = time.time()
    for run_id in range(0, args.num_runs):
        print(f"Run {run_id} starts......")
        t_start = time.time()
        for benchmark in benchmark_list:
            output_folder = f"{args.output_folder}/{benchmark}"
            output_folder_pktgen = f"{args.output_folder_pktgen}/{benchmark}"
            if BENCHMARK_portknock in benchmark:
                LOADER_NAME = "xdpex1"
                version_name_list = ["v1", "v2"]
            elif BENCHMARK_hhd in benchmark:
                LOADER_NAME = "xdpex1"
                version_name_list = ["v1", "v10"]
            elif BENCHMARK_token_bucket in benchmark:
                LOADER_NAME = "xdpex1"
                version_name_list = ["v1", "v4"]
            elif BENCHMARK_ddos_mitigator in benchmark:
                LOADER_NAME = "xdp_ddos_mitigator"
                version_name_list = ["v1", "v4"]
            elif BENCHMARK_nat_dp in benchmark:
                LOADER_NAME = "xdp_nat_dp"
                version_name_list = ["v1", "v3"]
            else:
                print(f"Benchmark {benchmark} not supported. Exit")
                sys.exit(0)
            print(f"Test benchmark {benchmark}")
            print(run_id, benchmark, LOADER_NAME, version_name_list,
                args.num_cores_max, args.duration, output_folder,
                output_folder_pktgen)
            test_benchmark(run_id, benchmark, version_name_list,
                args.num_cores_max, args.duration, output_folder,
                output_folder_pktgen)
        time_cost = time.time() - t_start
        print(f"Run {run_id} ends. time_cost: {time_cost}")
    time_cost = time.time() - t_start_experiments
    print(f"Experiments ends. time_cost: {time_cost}")
