import argparse
from os.path import exists
import subprocess
import os
import sys
import time
from os.path import expanduser
from client import send_command
from socket_commands import *
from utils import *

CLIENT_DIR = ""
CONFIG_file_xl170 = "config.xl170"
LOADER_NAME = ""
CLIENT=""
SERVER_IFACE = ""
MAX_RX_QUEUES = 32
NUM_SRCIP_DDOS = 0

DISABLE_prog_latency = False
DISABLE_prog_latency_ns = False
DISABLE_insn_latency = False
DISABLE_pcm = False
DISABLE_pktgen_measure = False
DISABLE_pktgen_measure_parallel = False
DISABLE_mlffr = False
BENCHMARK_portknock = "portknock"
BENCHMARK_hhd = "hhd"
BENCHMARK_ddos_mitigator = "ddos_mitigator"
BENCHMARK_token_bucket = "token_bucket"
BENCHMARK_nat_dp = "nat_dp"
BENCHMARK_xdpex1 = "xdpex1"
BENCHMARK_dummy = "dummy"

CPU_ARM = "arm"
CPU_INTEL = "intel"
CPU_AMD = "amd"

PKTGEN_PATH = None

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
    elif BENCHMARK_dummy in prog_name:
        benchmark = BENCHMARK_dummy
    else:
        benchmark = BENCHMARK_xdpex1
    versions = ["v10", "v11", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"]
    for v in versions:
        if v in prog_name:
            version = v
            break
    return benchmark, version

def get_prog_load_command(prog_name):
    benchmark, version = get_benchmark_version(prog_name)
    cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    if benchmark == BENCHMARK_ddos_mitigator:
        cmd += f" -A stats_srcip.txt -P {NUM_SRCIP_DDOS}"
    return cmd

def get_prog_tag():
    cmd = "bpftool prog show | grep xdp"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
    except:
        print_log ("ERROR: no xdp found! not able to get program tag")
        raise
        return
    tag = output.split()[5]
    print_log(f"program tag is {tag}")
    return tag

def run_cmd(cmd, wait=True):
    print_log(cmd)
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
    print_log(f"run_cmd_on_client: {res}")
    return res

def run_unmodified_cmd_on_client(client_cmd, client):
    res = send_command(client_cmd)
    print_log(f"run_cmd_on_client: {res}")
    return res

def kill_process_on_client(process, client):
    client_cmd = f"pkill -f {process} >/dev/null 2>&1 &"
    run_cmd_on_client(client_cmd, client)

def clean_environment(client, prog_name):
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    # stop packet generation
    kill_process_on_client("dpdk-replay", client)
    kill_process_on_client("measure.py", client)
    loader_cmd = get_prog_load_command(prog_name)
    run_cmd(f"pkill -f \"{loader_cmd}\"", wait=True)

def run_packet_generator(pcap_file, client):
    # send packets
    timestr = time.strftime("%Y%m%d-%H%M%S")
    config_file = f"config_{timestr}.yaml"
    config_file_path = f"{PKTGEN_PATH}/dpdk_replay_config/"
    NIC_PCIE = "0000:ca:00.0"
    client_cmd = f"python3 {PKTGEN_PATH}/create_dpdk_replay_config.py -o {config_file_path} --fname {config_file} --pcap {pcap_file} -n 1 --pcie {NIC_PCIE} --tx_queues 4 --numacore 1"
    run_unmodified_cmd_on_client(client_cmd, client)
    client_cmd = f"sudo {PKTGEN_PATH}/dpdk-replay --config {config_file_path}/{config_file} >log_dpdk_replay.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)
    # check if packet gen is stable
    client_cmd = CMD_CHECK_PKT_GEN_STABLE
    res = run_unmodified_cmd_on_client(client_cmd, client)
    time.sleep(5)

def pktgen_measure(client, output_path, dur):
    client_cmd = f"python3 {PKTGEN_PATH}measure.py -o {output_path} -t {dur} >log_pktgen_measure.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)

def set_up_configs(benchmark, version, n_cores):
    is_flow_affinity = False
    flow_affinity_version_dic = {
        BENCHMARK_hhd: ["v2", "v4"],
        BENCHMARK_ddos_mitigator: ["v2", "v5"],
        BENCHMARK_token_bucket: ["v5", "v6"],
        BENCHMARK_portknock: ["v4"],
        BENCHMARK_dummy: [],
    }
    hash_packet_fields_dic = {
        BENCHMARK_hhd: "sdfn",
        BENCHMARK_ddos_mitigator: "sd",
        BENCHMARK_token_bucket: "sdfn",
        BENCHMARK_portknock: "sd",
        BENCHMARK_dummy: "sdfn",
    }
    print_log(f"benchmark: {benchmark}")
    if benchmark not in flow_affinity_version_dic:
        print_log(f"Benchmark {benchmark} not supported. Exit")
        sys.exit(0)
    if benchmark not in hash_packet_fields_dic:
        print_log(f"Benchmark {benchmark} not supported. Exit")
        sys.exit(0)
    flow_affinity_versions = flow_affinity_version_dic[benchmark]
    hash_packet_fields = hash_packet_fields_dic[benchmark]
    if version in flow_affinity_versions:
        is_flow_affinity = True
    print_log(f"is_flow_affinity: {is_flow_affinity}")
    print_log(f"hash_packet_fields: {hash_packet_fields}")

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


    print_log(f"Display configurations: {benchmark}, {version}, {n_cores}")
    run_cmd(f"ethtool --show-nfc {SERVER_IFACE}")
    run_cmd(f"ethtool -l {SERVER_IFACE}")
    run_cmd(f"ethtool -n {SERVER_IFACE} rx-flow-hash tcp4")

def get_pcap_file(pcap_path, benchmark, version, n_cores, pcap_benchmark):
    # shared_state: shared_state_[#cores].pcap
    # flow_affinity: [benchmark]_flow_affinity.pcap
    # shared_nothing: [benchmark]_shared_nothing_[#cores].pcap
    VERSION_shared_state = "shared_state"
    VERSION_flow_affinity = "flow_affinity"
    VERSION_shared_nothing = "shared_nothing"
    version_type_dic = {
        BENCHMARK_hhd: {
            "v1": VERSION_shared_state,
            "v2": VERSION_flow_affinity,
            "v4": VERSION_flow_affinity,
            "v10": VERSION_shared_nothing,
            "v11": VERSION_shared_nothing,
        },
        BENCHMARK_ddos_mitigator: {
            "v1": VERSION_shared_state,
            "v2": VERSION_flow_affinity,
            "v4": VERSION_shared_nothing,
            "v5": VERSION_flow_affinity,
            "v6": VERSION_shared_nothing,
        },
        BENCHMARK_token_bucket: {
            "v1": VERSION_shared_state,
            "v4": VERSION_shared_nothing,
            "v5": VERSION_flow_affinity,
            "v6": VERSION_flow_affinity,
            "v7": VERSION_shared_nothing,
        },
        BENCHMARK_portknock: {
            "v1": VERSION_shared_state,
            "v2": VERSION_shared_nothing,
            "v4": VERSION_flow_affinity,
        },
        BENCHMARK_dummy: {
            "v1": VERSION_shared_state,
        },
    }
    if pcap_benchmark == benchmark:
        if benchmark not in version_type_dic:
            print_log(f"Benchmark {benchmark} not supported. Exit")
            sys.exit(0)
        if version not in version_type_dic[benchmark]:
            print_log(f"Benchmark {benchmark} {version} not supported. Exit")
            sys.exit(0)
        version_type = version_type_dic[benchmark][version]
        pcap_name = ""
        if version_type == VERSION_shared_state:
            pcap_name = f"{version_type}_{n_cores}.pcap"
        elif version_type == VERSION_flow_affinity:
            pcap_name = f"xdp_{benchmark}_flow_affinity.pcap"
        elif version_type == VERSION_shared_nothing:
            pcap_name = f"xdp_{benchmark}_shared_nothing_{n_cores}.pcap"
        else:
            print_log(f"version_type {version_type} not supported. Exit")
            sys.exit(0)
    else:
        # shared-nothing versions
        dummy_pcap_file_dic = {
            BENCHMARK_hhd: "v11",
            BENCHMARK_ddos_mitigator: "v6",
            BENCHMARK_token_bucket: "v7",
            BENCHMARK_portknock: "v2",
        }
        if pcap_benchmark not in dummy_pcap_file_dic:
            print_log(f"Benchmark {benchmark} for pcap benchmark {pcap_benchmark} not supported. Exit")
            sys.exit(0)
        shared_nothing_version = dummy_pcap_file_dic[pcap_benchmark]
        pcap_name = f"xdp_{pcap_benchmark}_shared_nothing_{n_cores}.pcap"
    pcap_file = f"{pcap_path}/{pcap_name}"
    return pcap_file


def run_test(prog_name, core_list, client, seconds, output_folder,
    output_folder_pktgen, pcap_path, pcap_benchmark):
    benchmark, version = get_benchmark_version(prog_name)
    n_cores = len(core_list)
    pcap_file = get_pcap_file(pcap_path, benchmark, version, n_cores, pcap_benchmark)
    # 1. print_log test name and environment configurations such as RSS
    print_log(f"Test {prog_name} across {len(core_list)} core(s) for {str(seconds)} seconds using pcap {pcap_file}...")
    if exists("tmp"):
        run_cmd("rm -rf tmp", wait=True)
    run_cmd("mkdir tmp", wait=True)
    set_up_configs(benchmark, version, len(core_list))

    # 2. attach xdp program
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    cmd = get_prog_load_command(prog_name)
    run_cmd_on_core(cmd, 0)

    # 3. run packet generator
    run_packet_generator(pcap_file, client)

    # 4. measure the xdp prorgam
    try:
        tag = get_prog_tag()
    except:
        print_log(f"ERROR: not able to get the tag of {prog_name}. Test stop...")
        clean_environment(client, prog_name)
        return

    # 4.3 use kernel stats to measure overall latency (nanoseconds)
    if not DISABLE_prog_latency_ns:
        if not DISABLE_pktgen_measure_parallel:
            pktgen_measure(client, f"{output_folder_pktgen}/prog_ns/", seconds)
        run_cmd("sudo sysctl -w kernel.bpf_stats_enabled=1", wait=True)
        time.sleep(seconds)
        run_cmd("sudo sysctl -w kernel.bpf_stats_enabled=0", wait=True)
        run_cmd("sudo bpftool prog show | grep \"xdp.*run_time_ns\" > tmp/prog_ns.txt", wait=True)
        time.sleep(20)

    # 4.4 use pcm to measure performance counters
    if not DISABLE_pcm:
        flag = False
        max_times = 3 # try at most 3 times
        count = 0
        while count < max_times:
            if not DISABLE_pktgen_measure_parallel:
                pktgen_measure(client, f"{output_folder_pktgen}/pcm/", seconds)
            run_cmd(f"sudo nohup pcm {seconds} -i=1 -csv=tmp/pcm.csv &", wait=False)
            run_cmd(f"sudo nohup pcm-memory {seconds} -i=1 -csv=tmp/pcm_memory.csv &", wait=False)
            time.sleep(seconds + 2)
            # check if measurement is successful
            file_size = os.path.getsize("tmp/pcm.csv")
            if file_size > 0:
                flag = True
            # check if flag is true
            if flag:
                break
            else:
                print("pcm measure NOT success: file size = 0")
                pcm_cmd = "pcm.*csv"
                run_cmd(f"sudo pkill -f \"{pcm_cmd}\"", wait=True)
                run_cmd("sudo rm -f tmp/pcm.csv", wait=True)
                run_cmd("sudo rm -f tmp/pcm_memory.csv", wait=True)
            count += 1
        time.sleep(20)

    # 4.5 run performance measurement on the packet generator
    if not DISABLE_pktgen_measure:
        pktgen_measure(client, f"{output_folder_pktgen}/no_profile/", seconds)
        time.sleep(seconds + 1)
        time.sleep(5)

    # 5. clean environment
    clean_environment(client, prog_name)
    time.sleep(5)

    # 6. move the files to the output folder
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    run_cmd("sudo rm -rf tmp", wait=True)
    time.sleep(5)


def measure_mlffr(prog_name, core_list, client, seconds, output_folder, pcap_path, pcap_benchmark):
    # (prog_name, core_list, client, seconds, output_folder, num_flows):
    # 1. print test name
    benchmark, version = get_benchmark_version(prog_name)
    pcap_file = get_pcap_file(pcap_path, benchmark, version, len(core_list), pcap_benchmark)
    print_log(f"Test mlffr {prog_name} across {len(core_list)} core(s) for {str(seconds)} seconds using pcap {pcap_file}...")
    if exists("tmp"):
        run_cmd("rm -rf tmp", wait=True)
    run_cmd("mkdir tmp", wait=True)
    set_up_configs(benchmark, version, len(core_list))

    # 2. attach xdp program
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    cmd = get_prog_load_command(prog_name)
    run_cmd_on_core(cmd, 0)

    # 3. send mlffr measurement command to the packet generator
    measure_time = seconds
    rate_high = 85
    rate_low = 0
    precision = 0.2
    paras = f"{pcap_file} {measure_time} {rate_high} {rate_low} {precision}"
    client_cmd = f"{CMD_MEASURE_MLFFR} {paras}"
    mlffr = run_unmodified_cmd_on_client(client_cmd, client)
    print(f"mlffr: {mlffr}")
    fout = open("tmp/mlffr.txt", "w")
    line = f"{mlffr}\n"
    fout.write(line)
    fout.close()

    # 4. clean environment
    clean_environment(client, prog_name)

    # 5. move the files to the output folder
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    time.sleep(3)
    run_cmd("sudo rm -rf tmp", wait=True)
    time.sleep(2)


def run_tests_versions(prog_name_prefix, core_num_min, core_num_max, duration,
                       output_folder, output_folder_pktgen, run_id, pcap_path, pcap_benchmark):
    if DISABLE_prog_latency_ns and DISABLE_pcm and DISABLE_pktgen_measure:
        return
    core_list = []
    for i in range(1, core_num_max + 1):
        core_list = [x for x in range(1, i + 1)]
        prog_name = f"{prog_name_prefix}_p{i}"
        output_folder_i = output_folder + "/" + str(i) + "/" + str(run_id)
        if not os.path.exists(output_folder_i):
            run_cmd("sudo mkdir -p " + output_folder_i, wait=True)
        output_folder_i_pktgen = output_folder_pktgen + "/" + str(i) + "/" + str(run_id)
        run_test(prog_name, core_list, CLIENT, duration, output_folder_i,
            output_folder_i_pktgen, pcap_path, pcap_benchmark)


def run_mlffr_versions(prog_name_prefix, core_num_min, core_num_max, duration,
                       output_folder, run_id, pcap_path, pcap_benchmark):
    if DISABLE_mlffr:
        return
    core_list = []
    for i in range(core_num_min, core_num_max + 1):
        core_list = [x for x in range(1, i + 1)]
        prog_name = f"{prog_name_prefix}_p{i}"
        output_folder_i = output_folder + "/" + str(i) + "/" + str(run_id)
        if not os.path.exists(output_folder_i):
            run_cmd("sudo mkdir -p " + output_folder_i, wait=True)
        measure_mlffr(prog_name, core_list, CLIENT, duration, output_folder_i,
            pcap_path, pcap_benchmark)


def read_machine_info_from_file(input_file):
    client = None
    server_iface = None
    client_dir = None
    client_keyword = "client"
    server_iface_keyword = "server_iface"
    client_dir_keyword = "client_dir"
    if not exists(input_file):
        print_log(f"ERROR: no such file {input_file}. Return client: None, server_iface: None, client_dir: None")
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
    num_cores_min, num_cores_max, duration, output_folder,
    output_folder_pktgen, pcap_path, pcap_benchmark):
    print_log(f"Benchmark {benchmark} run {run_id} starts......")
    t_start = time.time()
    for version in version_name_list:
        t_start_v = time.time()
        prog_name_prefix = f"{benchmark}_{version}"
        output_folder_version_dut = f"{output_folder}/{version}"
        output_folder_version_pktgen = f"{output_folder_pktgen}/{version}"
        if BENCHMARK_dummy in benchmark:
            output_folder_version_dut = f"{output_folder}/{pcap_benchmark}"
            output_folder_version_pktgen = f"{output_folder_pktgen}/{pcap_benchmark}"
        run_mlffr_versions(prog_name_prefix, num_cores_min, num_cores_max, duration,
            output_folder_version_dut, run_id, pcap_path, pcap_benchmark)
        run_tests_versions(prog_name_prefix, num_cores_min, num_cores_max, duration,
            output_folder_version_dut, output_folder_version_pktgen, run_id,
            pcap_path, pcap_benchmark)
        time_cost_v = time.time() - t_start_v
        print_log(f"Run {run_id} {version} test ends. time_cost: {time_cost_v}")
    time_cost = time.time() - t_start
    print_log(f"Benchmark {benchmark} run {run_id} ends. time_cost: {time_cost}")

# add pcap file
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-i', dest="pcap_path", type=str, help='Input path of pcap files', required=True)
    parser.add_argument('-o', dest="output_folder", type=str, help='Output path on DUT', required=True)
    parser.add_argument('--o_pktgen', dest="output_folder_pktgen", type=str, default=None, help='Output path on the packet generator, default is the same as output path on DUT', required=False)
    parser.add_argument('-b', dest="benchmark_list", type=str, default="all", help='XDP benchmark list, e.g., xdp_portknock,xdp_hhd. `all` means all benchmarks', required=False)
    parser.add_argument('-r', dest="num_runs", type=int, help='Total number of runs (greater than 1)', required=True)
    parser.add_argument('--start_rid', dest="start_rid", type=int, help='Start run id', default=0)
    parser.add_argument('--nc_max', dest="num_cores_max", type=int, help='Maximum number of cores (greater than 1)', required=True)
    parser.add_argument('--nc_min', dest="num_cores_min", type=int, help='Minimum number of cores (greater than nc_max)', default=1)
    parser.add_argument('-d', dest="duration", type=int, help='Duration for each test. Unit: seconds', required=True)
    parser.add_argument('--disable_prog_latency', action='store_true', help='Disable prog latency measurement', required=False)
    parser.add_argument('--disable_prog_latency_ns', action='store_true', help='Disable prog latency (nanoseconds, use kernel stats) measurement', required=False)
    parser.add_argument('--disable_insn_latency', action='store_true', help='Disable insn latency measurement', required=False)
    parser.add_argument('--disable_pcm', action='store_true', help='Disable pcm measurement', required=False)
    parser.add_argument('--disable_pktgen_measure_parallel', action='store_true', help='Disable pktgen measurement while measuring other metrics: round-trip latency and throughput', required=False)
    parser.add_argument('--disable_pktgen_measure', action='store_true', help='Disable pktgen measurement: round-trip latency and throughput', required=False)
    parser.add_argument('--disable_mlffr', action='store_true', help='Disable measuring MLFFR', required=False)
    parser.add_argument('--n_srcip_ddos', dest="n_srcip_ddos", type=int, help='# of srcips inserted into ddos blocklist', default=100)
    args = parser.parse_args()
    if args.output_folder_pktgen is None:
        args.output_folder_pktgen = args.output_folder
    if args.benchmark_list == "all":
        benchmark_list = [f"xdp_{BENCHMARK_portknock}", f"xdp_{BENCHMARK_hhd}",
                          f"xdp_{BENCHMARK_token_bucket}", f"xdp_{BENCHMARK_ddos_mitigator}",
                          f"xdp_{BENCHMARK_nat_dp}", f"xdp_{BENCHMARK_dummy}"]
    else:
        benchmark_list = args.benchmark_list.split(",")
    DISABLE_prog_latency = args.disable_prog_latency
    DISABLE_prog_latency_ns = args.disable_prog_latency_ns
    DISABLE_insn_latency = args.disable_insn_latency
    DISABLE_pcm = args.disable_pcm
    DISABLE_pktgen_measure_parallel = args.disable_pktgen_measure_parallel
    DISABLE_pktgen_measure = args.disable_pktgen_measure
    DISABLE_mlffr = args.disable_mlffr
    NUM_SRCIP_DDOS = args.n_srcip_ddos
    if DISABLE_prog_latency and DISABLE_prog_latency_ns and DISABLE_insn_latency and DISABLE_pcm and DISABLE_pktgen_measure and DISABLE_mlffr:
        sys.exit(0)
    # read client and server_iface from config.xl170
    CLIENT, SERVER_IFACE, CLIENT_DIR = read_machine_info_from_file(CONFIG_file_xl170)
    if CLIENT is None or SERVER_IFACE is None or CLIENT_DIR is None:
        sys.exit(0)

    PKTGEN_PATH = f"{CLIENT_DIR}/dpdk-burst-replay/src/"
    pcap_path = args.pcap_path
    version_name_list = []
    version_info_list = []
    pcap_benchmark_list = [] # this is only for xdp_dummy
    t_start_experiments = time.time()
    for run_id in range(args.start_rid, args.start_rid + args.num_runs):
        print_log(f"Run {run_id} starts......")
        t_start = time.time()
        for benchmark in benchmark_list:
            pcap_benchmark_list = [benchmark]
            output_folder = f"{args.output_folder}/{benchmark}"
            output_folder_pktgen = f"{args.output_folder_pktgen}/{benchmark}"
            if BENCHMARK_portknock in benchmark:
                LOADER_NAME = "xdpex1"
                version_name_list = ["v1", "v2", "v4"]
            elif BENCHMARK_hhd in benchmark:
                LOADER_NAME = "xdpex1"
                version_name_list = ["v1", "v4", "v11"]
            elif BENCHMARK_token_bucket in benchmark:
                LOADER_NAME = "xdpex1"
                version_name_list = ["v1", "v7", "v6"]
            elif BENCHMARK_ddos_mitigator in benchmark:
                LOADER_NAME = "xdp_ddos_mitigator"
                version_name_list = ["v1", "v5", "v6"]
            elif BENCHMARK_nat_dp in benchmark:
                LOADER_NAME = "xdp_nat_dp"
                version_name_list = ["v1", "v3"]
            elif BENCHMARK_dummy in benchmark:
                LOADER_NAME = "xdp_dummy"
                version_name_list = ["v1"]
                pcap_benchmark_list = ["xdp_dummy", "xdp_hhd", "xdp_ddos_mitigator", "xdp_token_bucket", "xdp_portknock"]
            else:
                print_log(f"Benchmark {benchmark} not supported. Exit")
                sys.exit(0)
            # Remove `xdp_` from each string
            pcap_benchmark_list = [string[4:] for string in pcap_benchmark_list]
            print_log(f"Test benchmark {benchmark}")
            string = f"{run_id} {benchmark} {LOADER_NAME}"
            string += f" {version_name_list} {args.num_cores_min} {args.num_cores_max}"
            string += f" {args.duration} {output_folder} {output_folder_pktgen}"
            print_log(string)
            for pcap_benchmark in pcap_benchmark_list:
                test_benchmark(run_id, benchmark, version_name_list,
                    args.num_cores_min, args.num_cores_max, args.duration,
                    output_folder, output_folder_pktgen, pcap_path, pcap_benchmark)
        time_cost = time.time() - t_start
        print_log(f"Run {run_id} ends. time_cost: {time_cost}")
    time_cost = time.time() - t_start_experiments
    print_log(f"Experiments ends. time_cost: {time_cost}")
