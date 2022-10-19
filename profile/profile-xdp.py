# nohup sudo sh -c 'python3 -u profile-xdp.py  1>log.txt 2>err.txt &'

import argparse
from os.path import exists
import subprocess
import os
import sys
import time
from os.path import expanduser

home = expanduser("~")
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
SERVER_CPU = ""

DISABLE_prog_latency = False
DISABLE_prog_latency_ns = False
DISABLE_insn_latency = False
BENCHMARK_portknock = "portknock"
BENCHMARK_hhd = "hhd"
BENCHMARK_xdpex1 = "xdpex1"

CPU_ARM = "arm"
CPU_INTEL = "intel"
CPU_AMD = "amd"

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

def clean_environment(client, prog_name):
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    # stop packet generation
    # todo
    client_cmd = f"pkill -f send_udp_packets_for_xl170.py >/dev/null 2>&1 &"
    cmd = f"ssh -p 22 {client} \"nohup sudo sh -c '{client_cmd}'\""
    run_cmd(cmd)
    client_cmd = f"pkill tcpreplay >/dev/null 2>&1 &"
    cmd = f"ssh -p 22 {client} \"nohup sudo sh -c '{client_cmd}'\""
    run_cmd(cmd)
    loader_cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd(f"pkill -f \"{loader_cmd}\"", wait=True)

def run_packet_generator(benchmark, version, core_list, client):
    # start packet generation
    for i in core_list:
        client_cmd = ""
        if benchmark == BENCHMARK_portknock:
            rss_para = f"{SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras = f"loop {version} {rss_para} {len(core_list)}"
            client_cmd = f"sh -c 'sudo python3 -u {home}/bpf-profile/profile/send_udp_packets_portknock.py {paras} >log.txt 2>&1 &'"
        elif benchmark == BENCHMARK_hhd:
            paras = "v1"
            if SERVER_CPU != CPU_ARM:
                paras += f" {SRC_MAC_PRE}{str(SRC_MAC_POST_START+i)}"
            else:
                paras += f" {SRC_IP_PRE}{str(SRC_IP_POST_START+i)}"
            paras += f" {len(core_list)}"
            client_cmd = f"sh -c 'sudo python3 -u {home}/bpf-profile/profile/send_udp_packets_hhd.py {paras} >log.txt 2>&1 &'"
        else:
            client_cmd = f"sh -c 'sudo python3 -u {home}/bpf-profile/profile/send_udp_packets_for_xl170.py {str(START_DPORT+i)} >log.txt 2>&1 &'"
        cmd = f"ssh -p 22 {client} \"nohup sudo {client_cmd}\""
        run_cmd(cmd)

def get_benchmark_version(prog_name):
    benchmark = None
    version = None
    if BENCHMARK_portknock in prog_name:
        benchmark = BENCHMARK_portknock
    elif BENCHMARK_hhd in prog_name:
        benchmark = BENCHMARK_hhd
    else:
        benchmark = BENCHMARK_xdpex1
    versions = ["v1", "v2", "v3"]
    for v in versions:
        if v in prog_name:
            version = v
            break
    return benchmark, version

def run_test(prog_name, core_list, client, seconds, output_folder):
    # 1. print test name
    print("Test",  prog_name, "across", len(core_list), "core(s) for", str(seconds), "seconds...")
    if exists("tmp"):
        run_cmd("rm -rf tmp", wait=True)
    run_cmd("mkdir tmp", wait=True)

    benchmark, version = get_benchmark_version(prog_name)
    run_packet_generator(benchmark, version, core_list, client)

    # 2. attach xdp program
    run_cmd(f"sudo bpftool net detach xdp dev {SERVER_IFACE}")
    cmd = f"./{LOADER_NAME} -I {prog_name} -N {SERVER_IFACE}"
    run_cmd_on_core(cmd, 0)

    # 3. wait some seconds for the packet generation start sending packets
    # wait until tcpreplay starts
    time.sleep(10)

    # 4. measure the xdp prorgam
    try:
        tag = get_prog_tag()
    except:
        print(f"ERROR: not able to get the tag of {prog_name}. Test stop...")
        clean_environment(client, prog_name)
        return

    # 4.1 use perf to do instruction level sampling
    if not DISABLE_insn_latency:
        tmp_out_file = "tmp/" + prog_name + "_perf.data"
        core_list_str = ",".join([str(x) for x in core_list])
        cmd = "sudo ./perf record -F 25250 --cpu " + core_list_str + " -o " + tmp_out_file + " sleep " + str(seconds)
        run_cmd(cmd, wait=True)
        cmd = "sudo ./perf annotate -l -P bpf_prog_" + tag + "_xdp_prog" + " -i " + tmp_out_file + " > tmp/perf.txt"
        run_cmd(cmd, wait=True)
        run_cmd("sudo rm -rf " + tmp_out_file, wait=True)

    # 4.2 use bpftool to get overall latency (cycles)
    # todo: remove "llc_misses" since not able to create this event on AMD machines
    if not DISABLE_prog_latency:
        cmd = "sudo bpftool prog profile tag " + tag + " duration " + str(seconds) + " cycles instructions > tmp/prog.txt"
        run_cmd(cmd, wait=True)

    # 4.3 use kernel stats to measure overall latency (nanoseconds)
    if not DISABLE_prog_latency_ns:
        run_cmd("sudo sysctl -w kernel.bpf_stats_enabled=1", wait=True)
        time.sleep(seconds)
        run_cmd("sudo sysctl -w kernel.bpf_stats_enabled=0", wait=True)
        run_cmd("sudo bpftool prog show | grep \"xdp.*run_time_ns\" > tmp/prog_ns.txt", wait=True)

    # 5. clean environment
    clean_environment(client, prog_name)

    # 6. move the files to the output folder
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    run_cmd("sudo rm -rf tmp", wait=True)
    time.sleep(5)

def run_tests_versions(prog_name_prefix, core_num_max, duration, output_folder, run_id):
    core_list = []
    for i in range(1, core_num_max + 1):
        core_list.append(i)
        prog_name = f"{prog_name_prefix}_p{i}"
        output_folder_i = output_folder + "/" + str(i) + "/" + str(run_id)
        run_cmd("sudo mkdir -p " + output_folder_i, wait=True)
        run_test(prog_name, core_list, CLIENT, duration, output_folder_i)

def read_machine_info_from_file(input_file):
    client = None
    server_iface = None
    server_cpu = None
    client_keyword = "client"
    server_iface_keyword = "server_iface"
    server_cpu_keyword = "server_cpu"
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return client: None, server_iface: None")
        return None, None
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(":", 1) # split on first occurrence
        if len(line) < 2:
            continue
        if line[0] == client_keyword:
            client = line[1].strip()
        elif line[0] == server_iface_keyword:
            server_iface = line[1].strip()
        elif line[0] == server_cpu_keyword:
            server_cpu = line[1].strip()
    f.close()
    return client, server_iface, server_cpu

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-o', dest="output_folder", type=str, help='Output path', required=True)
    parser.add_argument('-b', dest="prog_name", type=str, help='Benchmark', required=True)
    parser.add_argument('-v', dest="versions", type=str, help='Version names for the benchmark', required=True)
    parser.add_argument('-l', dest="loader_name", type=str, help='Program used for loading benchmark', required=True)
    parser.add_argument('-r', dest="num_runs", type=int, help='Total number of runs (greater than 1)', required=True)
    parser.add_argument('--nc_max', dest="num_cores_max", type=int, help='Maximum number of cores (greater than 1)', required=True)
    parser.add_argument('-d', dest="duration", type=int, help='Duration for each test. Unit: seconds', required=True)
    parser.add_argument('--disable_prog_latency', action='store_true', help='Disable prog latency measurement', required=False)
    parser.add_argument('--disable_prog_latency_ns', action='store_true', help='Disable prog latency (nanoseconds, use kernel stats) measurement', required=False)
    parser.add_argument('--disable_insn_latency', action='store_true', help='Disable insn latency measurement', required=False)
    args = parser.parse_args()
    version_name_list = args.versions.split(",")
    LOADER_NAME = args.loader_name
    DISABLE_prog_latency = args.disable_prog_latency
    DISABLE_prog_latency_ns = args.disable_prog_latency_ns
    DISABLE_insn_latency = args.disable_insn_latency
    if DISABLE_prog_latency and DISABLE_prog_latency_ns and DISABLE_insn_latency:
        sys.exit(0)
    # read client and server_iface from config.xl170
    CLIENT, SERVER_IFACE, SERVER_CPU = read_machine_info_from_file(CONFIG_file_xl170)
    if CLIENT is None or SERVER_IFACE is None:
        sys.exit(0)
    for run_id in range(0, args.num_runs):
        print(f"Run {run_id} starts......")
        for version in version_name_list:
            prog_name_prefix = f"{args.prog_name}_{version}"
            output_folder_version = f"{args.output_folder}/{version}"
            run_tests_versions(prog_name_prefix, args.num_cores_max, args.duration, output_folder_version, run_id)
