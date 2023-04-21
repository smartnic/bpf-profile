# nohup sudo sh -c 'python3 -u profile-xdp.py  1>log.txt 2>err.txt &'

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
START_DPORT = 12
START_SPORT = 53

# src mac is used for xdp_hdd on intel/amd machines
SRC_MAC_PRE = "10:10:10:10:10:"
SRC_MAC_POST_START = 10 # src mac with 10:10:10:10:10:10 goes to cpu 0 on the server
# src ip is used for RSS for portknock
SRC_IP_PRE = "10.10.1."
SRC_IP_POST_START = 0 # src ip with 10.10.1.0 goes to cpu 0 on the server

CONFIG_file_xl170 = "config.xl170"
LOADER_NAME = ""
CLIENT=""
SERVER_IFACE = ""

DISABLE_prog_latency = False
DISABLE_prog_latency_ns = False
DISABLE_insn_latency = False
DISABLE_pcm = False
DISABLE_trex_measure = False
DISABLE_trex_measure_parallel = False
DISABLE_mlffr = False
BENCHMARK_portknock = "portknock"
BENCHMARK_hhd = "hhd"
BENCHMARK_ddos_mitigator = "ddos_mitigator"
BENCHMARK_token_bucket = "token_bucket"
BENCHMARK_nat_dp = "nat_dp"
BENCHMARK_xdpex1 = "xdpex1"

CPU_ARM = "arm"
CPU_INTEL = "intel"
CPU_AMD = "amd"

PKTGEN_SCAPY = "scapy"
PKTGEN_TREX = "trex"
PKTGEN_input = ""
TREX_PATH = None

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
    # todo
    kill_process_on_client("send_udp_packets_for_xl170.py", client)
    kill_process_on_client("tcpreplay", client)
    kill_process_on_client("t-rex-64", client)
    kill_process_on_client("run_trex.py", client)
    loader_cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd(f"pkill -f \"{loader_cmd}\"", wait=True)
    pcm_cmd = "sudo nohup pcm"
    run_cmd(f"sudo pkill -f \"{pcm_cmd}\"", wait=True)

def run_packet_generator_scapy(benchmark, version, core_list, client):
    # start packet generation
    for i in core_list:
        client_cmd = ""
        if benchmark == BENCHMARK_portknock:
            rss_para = f"{SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras = f"loop {version} {rss_para} {len(core_list)}"
            client_cmd = f"sudo python3 -u {CLIENT_DIR}/bpf-profile/profile/send_udp_packets_portknock.py {paras} >log.txt 2>&1 &"
        elif benchmark == BENCHMARK_hhd:
            rss_para = f"{SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras = f"{version} {rss_para} {len(core_list)}"
            client_cmd = f"sudo python3 -u {CLIENT_DIR}/bpf-profile/profile/send_udp_packets_hhd.py {paras} >log.txt 2>&1 &"
        elif benchmark == BENCHMARK_ddos_mitigator:
            rss_para = f"{SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras = f"{version} {rss_para} {len(core_list)}"
            client_cmd = f"sudo python3 -u {CLIENT_DIR}/bpf-profile/profile/send_udp_packets_ddos_mitigator.py {paras} >log.txt 2>&1 &"
        elif benchmark == BENCHMARK_token_bucket:
            rss_para = f"{SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras = f"{version} {rss_para} {len(core_list)}"
            client_cmd = f"sudo python3 -u {CLIENT_DIR}/bpf-profile/profile/send_udp_packets_token_bucket.py {paras} >log.txt 2>&1 &"
        elif benchmark == BENCHMARK_nat_dp:
            rss_para = f"{SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras = f"{version} {rss_para} {len(core_list)}"
            client_cmd = f"sudo python3 -u {CLIENT_DIR}/bpf-profile/profile/send_udp_packets_nat_dp.py {paras} >log.txt 2>&1 &"
        else:
            client_cmd = f"sudo python3 -u {CLIENT_DIR}/bpf-profile/profile/send_udp_packets_for_xl170.py {str(START_DPORT+i)} >log.txt 2>&1 &"
        run_cmd_on_client(client_cmd, client)
    # wait some seconds for the packet generation start sending packets
    # wait until tcpreplay starts
    time.sleep(10)

def start_trex_server(client):
    client_cmd = f"sudo bash {TREX_PATH}start_trex_server.sh {TREX_PATH} >log_trex_server.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)
    time.sleep(10)

def run_packet_generator_trex(benchmark, version, core_list, client, num_flows, tx_rate, base_pkt_len):
    # start trex server
    start_trex_server(client)
    # send packets for 10000 seconds
    print(f"run_packet_generator_trex: {base_pkt_len}")
    client_cmd = f"sudo bash {TREX_PATH}run_trex.sh {TREX_PATH} {benchmark} {version} 10000 {tx_rate} {len(core_list)} {num_flows} {base_pkt_len} >log.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)
    # check if packet gen is stable
    client_cmd = CMD_CHECK_PKT_GEN_STABLE
    res = run_unmodified_cmd_on_client(client_cmd, client)

def run_packet_generator(benchmark, version, core_list, client, num_flows, tx_rate, base_pkt_len):
    if PKTGEN_input == PKTGEN_SCAPY:
        run_packet_generator_scapy(benchmark, version, core_list, client)
    elif PKTGEN_input == PKTGEN_TREX:
        run_packet_generator_trex(benchmark, version, core_list, client, num_flows, tx_rate, base_pkt_len)
    else:
        print(f"ERROR: pktgen {PKTGEN_input} is not {PKTGEN_SCAPY} or {PKTGEN_TREX}")

def start_trex_measure(client, output_path):
    client_cmd = f"sudo python3 {TREX_PATH}trex_measure_start.py -o {TREX_PATH} -trex_stats {output_path} >log_trex_measure_start.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)

def stop_trex_measure(client):
    client_cmd = f"sudo python3 {TREX_PATH}trex_measure_stop.py -o {TREX_PATH} >log_trex_measure_stop.txt 2>&1 &"
    run_cmd_on_client(client_cmd, client)

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

def measure_mlffr(prog_name, core_list, client, seconds, output_folder, num_flows):
    if PKTGEN_input != PKTGEN_TREX:
        print("ERROR: packet generator should be trex for measuring mlffr")
        return
    # 1. print test name
    print("Test mlffr ",  prog_name, "across", len(core_list), "core(s) for", str(seconds), "seconds...")
    if exists("tmp"):
        run_cmd("rm -rf tmp", wait=True)
    run_cmd("mkdir tmp", wait=True)

    # 2. attach xdp program
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd_on_core(cmd, 0)

    # 3. start trex server
    start_trex_server(client)

    # 4. send mlffr measurement command to the packet generator
    benchmark, version = get_benchmark_version(prog_name)
    num_cores = len(core_list)
    measure_time = seconds
    rate_high = 27.2
    rate_low = 0
    precision = 0.1
    paras = f"{benchmark} {version} {num_cores} {num_flows} {measure_time} {rate_high} {rate_low} {precision}"
    client_cmd = f"{CMD_MEASURE_MLFFR} {paras}"
    mlffr = run_unmodified_cmd_on_client(client_cmd, client)
    print(f"mlffr: {mlffr}")
    fout = open("tmp/mlffr.txt", "w")
    line = f"{mlffr}\n"
    fout.write(line)
    fout.close()

    # 5. clean environment
    clean_environment(client, prog_name)

    # 6. move the files to the output folder
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    run_cmd("sudo rm -rf tmp", wait=True)
    time.sleep(5)


def run_test(prog_name, core_list, client, seconds, output_folder,
             output_folder_trex, num_flows, tx_rate = '0', base_pkt_len = 64):
    # 1. print test name
    print("Test",  prog_name, "across", len(core_list), "core(s) for", str(seconds), "seconds...")
    if exists("tmp"):
        run_cmd("rm -rf tmp", wait=True)
    run_cmd("mkdir tmp", wait=True)

    # 2. attach xdp program
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd_on_core(cmd, 0)

    # 3. run packet generator
    benchmark, version = get_benchmark_version(prog_name)
    run_packet_generator(benchmark, version, core_list, client, num_flows, tx_rate, base_pkt_len)

    # 4. measure the xdp prorgam
    try:
        tag = get_prog_tag()
    except:
        print(f"ERROR: not able to get the tag of {prog_name}. Test stop...")
        clean_environment(client, prog_name)
        return

    # 4.1 use perf to do instruction level sampling
    if not DISABLE_insn_latency:
        if not DISABLE_trex_measure_parallel:
            start_trex_measure(client, f"{output_folder_trex}/perf/")
        tmp_out_file = "tmp/" + prog_name + "_perf.data"
        core_list_str = ",".join([str(x) for x in core_list])
        cmd = "sudo ./perf record -F 25250 --cpu " + core_list_str + " -o " + tmp_out_file + " sleep " + str(seconds)
        run_cmd(cmd, wait=True)
        cmd = "sudo ./perf annotate -l -P bpf_prog_" + tag + "_xdp_prog" + " -i " + tmp_out_file + " > tmp/perf.txt"
        run_cmd(cmd, wait=True)
        run_cmd("sudo rm -rf " + tmp_out_file, wait=True)
        if not DISABLE_trex_measure_parallel:
            stop_trex_measure(client)
        time.sleep(20)

    # 4.2 use bpftool to get overall latency (cycles)
    # todo: remove "llc_misses" since not able to create this event on AMD machines
    if not DISABLE_prog_latency:
        if not DISABLE_trex_measure_parallel:
            start_trex_measure(client, f"{output_folder_trex}/prog/")
        cmd = "sudo bpftool prog profile tag " + tag + " duration " + str(seconds) + " cycles instructions > tmp/prog.txt"
        run_cmd(cmd, wait=True)
        if not DISABLE_trex_measure_parallel:
            stop_trex_measure(client)
        time.sleep(20)

    # 4.3 use kernel stats to measure overall latency (nanoseconds)
    if not DISABLE_prog_latency_ns:
        if not DISABLE_trex_measure_parallel:
            start_trex_measure(client, f"{output_folder_trex}/prog_ns/")
        run_cmd("sudo sysctl -w kernel.bpf_stats_enabled=1", wait=True)
        time.sleep(seconds)
        run_cmd("sudo sysctl -w kernel.bpf_stats_enabled=0", wait=True)
        if not DISABLE_trex_measure_parallel:
            stop_trex_measure(client)
        run_cmd("sudo bpftool prog show | grep \"xdp.*run_time_ns\" > tmp/prog_ns.txt", wait=True)
        time.sleep(20)

    # 4.4 use pcm to measure performance counters
    if not DISABLE_pcm:
        if not DISABLE_trex_measure_parallel:
            start_trex_measure(client, f"{output_folder_trex}/pcm/")
        run_cmd(f"sudo nohup pcm {seconds} -i=1 -csv=tmp/pcm.csv &", wait=False)
        run_cmd(f"sudo nohup pcm-memory {seconds} -i=1 -csv=tmp/pcm_memory.csv &", wait=False)
        time.sleep(seconds + 2)
        if not DISABLE_trex_measure_parallel:
            stop_trex_measure(client)
        time.sleep(20)

    # 4.5 run trex measurement on the packet generator
    if not DISABLE_trex_measure:
        start_trex_measure(client, f"{output_folder_trex}/no_profile/")
        time.sleep(seconds)
        stop_trex_measure(client)
        time.sleep(5)

    # 5. clean environment
    clean_environment(client, prog_name)

    # 6. move the files to the output folder
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    run_cmd("sudo rm -rf tmp", wait=True)
    time.sleep(5)

def run_tests_versions(prog_name_prefix, core_num_max, duration,
                       output_folder, output_folder_trex, run_id,
                       num_flows, tx_rate, base_pkt_len):
    if DISABLE_prog_latency and DISABLE_prog_latency_ns and DISABLE_insn_latency and DISABLE_pcm and DISABLE_trex_measure:
        return
    core_list = []
    for i in range(1, core_num_max + 1):
        core_list.append(i)
        prog_name = f"{prog_name_prefix}_p{i}"
        output_folder_i = output_folder + "/" + str(i) + "/" + str(run_id)
        run_cmd("sudo mkdir -p " + output_folder_i, wait=True)
        output_folder_i_trex = output_folder_trex + "/" + str(i) + "/" + str(run_id)
        run_test(prog_name, core_list, CLIENT, duration, output_folder_i,
            output_folder_i_trex, num_flows, tx_rate, base_pkt_len)

def run_mlffr_versions(prog_name_prefix, core_num_max, duration,
                       output_folder, run_id, num_flows):
    if DISABLE_mlffr:
        return
    core_list = []
    for i in range(1, core_num_max + 1):
        core_list.append(i)
        prog_name = f"{prog_name_prefix}_p{i}"
        output_folder_i = output_folder + "/" + str(i) + "/" + str(run_id)
        run_cmd("sudo mkdir -p " + output_folder_i, wait=True)
        measure_mlffr(prog_name, core_list, CLIENT, duration, output_folder_i, num_flows)

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-o', dest="output_folder", type=str, help='Output path on DUT', required=True)
    parser.add_argument('--o_trex', dest="output_folder_trex", type=str, default=None, help='Output path on trex machine, default is the same as output path on DUT', required=False)
    parser.add_argument('-b', dest="prog_name", type=str, help='Benchmark', required=True)
    parser.add_argument('-v', dest="versions", type=str, help='Version names for the benchmark', required=True)
    parser.add_argument('-l', dest="loader_name", type=str, help='Program used for loading benchmark', required=True)
    parser.add_argument('-r', dest="num_runs", type=int, help='Total number of runs (greater than 1)', required=True)
    parser.add_argument('--nc_max', dest="num_cores_max", type=int, help='Maximum number of cores (greater than 1)', required=True)
    parser.add_argument('-d', dest="duration", type=int, help='Duration for each test. Unit: seconds', required=True)
    parser.add_argument('--disable_prog_latency', action='store_true', help='Disable prog latency measurement', required=False)
    parser.add_argument('--disable_prog_latency_ns', action='store_true', help='Disable prog latency (nanoseconds, use kernel stats) measurement', required=False)
    parser.add_argument('--disable_insn_latency', action='store_true', help='Disable insn latency measurement', required=False)
    parser.add_argument('--disable_pcm', action='store_true', help='Disable pcm measurement', required=False)
    parser.add_argument('--disable_trex_measure_parallel', action='store_true', help='Disable trex measurement while measuring other metrics: round-trip latency and throughput', required=False)
    parser.add_argument('--disable_trex_measure', action='store_true', help='Disable trex measurement: round-trip latency and throughput', required=False)
    parser.add_argument('--disable_mlffr', action='store_true', help='Measure MLFFR', required=False)
    parser.add_argument('--pktgen', dest="pktgen", type=str, help='Packet generator: scapy or trex', required=True)
    parser.add_argument('--tx_rate_list', dest="tx_rate_list", default="1", help='TX rate (Mpps) list when pktgen is trex, e.g., 1,3. The default list is [1].', required=False)
    parser.add_argument('--nf_list', dest="num_flows_list", default="1", help='Number of flows sent to each core, e.g., 1,3. The default list is [1].', required=False)
    parser.add_argument('--pkt_len', dest="base_pkt_len", type=int, default=64, help='base packet length (>=64)', required=False)
    args = parser.parse_args()
    if args.output_folder_trex is None:
        args.output_folder_trex = args.output_folder
    args.base_pkt_len = max(64, args.base_pkt_len)
    version_name_list = args.versions.split(",")
    LOADER_NAME = args.loader_name
    DISABLE_prog_latency = args.disable_prog_latency
    DISABLE_prog_latency_ns = args.disable_prog_latency_ns
    DISABLE_insn_latency = args.disable_insn_latency
    DISABLE_pcm = args.disable_pcm
    DISABLE_trex_measure_parallel = args.disable_trex_measure_parallel
    DISABLE_trex_measure = args.disable_trex_measure
    DISABLE_mlffr = args.disable_mlffr
    if DISABLE_prog_latency and DISABLE_prog_latency_ns and DISABLE_insn_latency and DISABLE_pcm and DISABLE_trex_measure and DISABLE_mlffr:
        sys.exit(0)
    PKTGEN_input = args.pktgen
    if PKTGEN_input != PKTGEN_SCAPY and PKTGEN_input != PKTGEN_TREX:
        sys.exit(0)
    # read client and server_iface from config.xl170
    CLIENT, SERVER_IFACE, CLIENT_DIR = read_machine_info_from_file(CONFIG_file_xl170)
    if CLIENT is None or SERVER_IFACE is None or CLIENT_DIR is None:
        sys.exit(0)

    TREX_PATH = f"{CLIENT_DIR}/MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64/v2.87/"
    tx_rate_list = args.tx_rate_list.split(',') # it won't be used by PKTGEN_SCAPY
    num_flows_list = args.num_flows_list.split(',') # it won't be used by PKTGEN_SCAPY
    for run_id in range(0, args.num_runs):
        print(f"Run {run_id} starts......")
        t_start = time.time()
        for num_flows in num_flows_list:
            # mlffr should have a different loop, not reply on tx_rate_list
            for version in version_name_list:
                t_start_v = time.time()
                prog_name_prefix = f"{args.prog_name}_{version}"
                output_folder_version_dut = f"{args.output_folder}/{num_flows}/{version}"
                run_mlffr_versions(prog_name_prefix, args.num_cores_max, args.duration,
                    output_folder_version_dut, run_id, num_flows)
                time_cost_v = time.time() - t_start_v
                print(f"Run {run_id} {version} mlffr ends. time_cost: {time_cost_v}")
            for tx_rate in tx_rate_list:
                for version in version_name_list:
                    t_start_v = time.time()
                    prog_name_prefix = f"{args.prog_name}_{version}"
                    output_folder_version_dut = f"{args.output_folder}/{num_flows}/{tx_rate}/{version}"
                    output_folder_version_trex = f"{args.output_folder_trex}/{num_flows}/{tx_rate}/{version}"
                    run_tests_versions(prog_name_prefix, args.num_cores_max, args.duration,
                        output_folder_version_dut, output_folder_version_trex, run_id, num_flows, tx_rate,
                        args.base_pkt_len)
                    time_cost_v = time.time() - t_start_v
                    print(f"Run {run_id} {version} test ends. time_cost: {time_cost_v}")
        time_cost = time.time() - t_start
        print(f"Run {run_id} ends. time_cost: {time_cost}")
