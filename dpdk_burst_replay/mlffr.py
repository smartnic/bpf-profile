import time
import csv
from os.path import exists
import subprocess
import os
import numpy as np
from create_dpdk_replay_config import create_dpdk_replay_config


CONFIG_file_xl170 = "config.xl170"
PKTGEN_PATH = None


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


def print_log(string):
    print(string, flush=True)


def run_cmd(cmd, wait=True):
    # print_log(cmd)
    if wait is True:
        process = subprocess.Popen(cmd, shell=True, close_fds=True)
        process.wait()
    else:
        os.system(cmd)


def get_stats():
    timestr = time.strftime("%Y%m%d-%H%M%S")
    stats_file = f"eth_stat_output_{timestr}.txt"
    if exists(stats_file):
        run_cmd(f"rm -f {stats_file}")
    get_stats_cmd = f"bash eth_stat.sh ens114np0 {stats_file} > /dev/null 2>&1"
    run_cmd(get_stats_cmd) # block until get stats
    if not exists(stats_file):
        print_log(f"ERROR: no such file {stats_file}.")
        return None
    stats_list = {}
    f = open(stats_file, "r")
    for line in f:
        str_list = line.split()
        if len(str_list) < 4:
            return None
        stats_list["rx_pps"] = float(str_list[0])
        stats_list["tx_pps"] = float(str_list[1])
        stats_list["rx_bps"] = float(str_list[2])
        stats_list["tx_bps"] = float(str_list[3])
    f.close()
    # print_log(stats_list)
    run_cmd(f"rm -f {stats_file}")
    return stats_list


def run_packet_generator_async(rate, pcap_file):
    # send packets
    timestr = time.strftime("%Y%m%d-%H%M%S")
    config_file = f"config_{timestr}.yaml"
    config_file_path = f"{PKTGEN_PATH}/dpdk_replay_config/"
    NIC_PCIE = "0000:ca:00.0"
    num_cores_to_run_pkt_gen = 1
    tx_queues = 4
    numacore = 1
    create_dpdk_replay_config(num_cores_to_run_pkt_gen, pcap_file, tx_queues, numacore, rate,
        NIC_PCIE, config_file_path, config_file)
    cmd = f"sudo {PKTGEN_PATH}/dpdk-replay --config {config_file_path}/{config_file} >log_dpdk_replay.txt 2>&1 &"
    run_cmd(cmd, False)
    time.sleep(5)
    return f"{config_file_path}/{config_file}"


def stop_packet_generator(config_file):
    run_cmd(f"sudo pkill -f dpdk-replay", wait=True)
    if os.path.exists(config_file):
        run_cmd(f"rm -f {config_file}")


def measure_rx(rate, measure_time, pcap_file):
    expected_actual_rate = (rate-rate*0.01) * pow(10,6)
    print_log(f"Expected actual rate: {expected_actual_rate} pps, rate: {rate} mpps")
    # start packet generator (asynchronously)
    config_file = run_packet_generator_async(rate, pcap_file)
    # wait for enough time to rx/tx rates are stable
    print_log("Wait for measurement......")
    max_wait_time = 30.0
    time.sleep(max_wait_time)
    # measure rx
    print_log("Start measurement......")
    t_start = time.time()
    # 1. get statistics every 0.5 second
    rx_pps_list = []
    count = 0
    while True:
        # 2. Check whether to stop measuring
        dur = time.time() - t_start
        if dur >= measure_time:
            print_log("Stop measurement")
            break
        time.sleep(0.5)
        stats = get_stats()
        if "tx_pps" not in stats:
            continue
        tx_pps = stats['tx_pps']
        if tx_pps >= expected_actual_rate:
            if "rx_pps" not in stats:
                continue
            rx_pps_list.append(stats["rx_pps"])
            count += 1
    # 3. Stop packet generator
    stop_packet_generator(config_file)
    # 4. Return rx rate in mpps
    rx_pps = 0.0
    if len(rx_pps_list) > 0:
        rx_pps = np.mean(rx_pps_list)
    print_log(f"rx = {rx_pps}, count = {count}")
    return (rx_pps / pow(10,6))


def measure_mlffr(pcap_file, measure_time, rate_high, rate_low, precision):
    rate_high = round(rate_high, 2)
    rate_low = round(rate_low, 2)
    _, _, CLIENT_DIR = read_machine_info_from_file(CONFIG_file_xl170)
    global PKTGEN_PATH
    PKTGEN_PATH = f"{CLIENT_DIR}/dpdk-burst-replay/src/"
    print_log(f"measure mlffr: {pcap_file}")
    print_log(f"{rate_low} mpps - {rate_high} mpps, precision: {precision} mpps")
    threshold = 0.04 # if (tx - rx) / tx <= threshold, update mlffr
    # set the initial value for mlffr
    mlffr = 0.0
    if rate_high < rate_low:
        print_log("[measure_mlffr] error: rate_high < rate_low")
        return mlffr
    if rate_high < 0 or rate_low < 0:
        print_log("[measure_mlffr] error: rate_high and rate_low should > 0")
        return mlffr
    while True:
        print_log(f"\n[measure_mlffr] rate_low = {rate_low}, rate_high = {rate_high}")
        # 1. check whether (rate_high - rate_low) < precision
        if (rate_high - rate_low) < precision:
            break
        # 2. measure rx under tx
        tx = (rate_high + rate_low) / 2
        tx = round(tx, 2)
        print_log(f"[measure_mlffr] tx = {tx}")
        rx = measure_rx(tx, measure_time, pcap_file)
        delta = (tx - rx) / tx
        print_log(f"[measure_mlffr] rx = {rx}, tx = {tx}, delta = {delta}")
        if delta <= threshold:
            mlffr = tx
            rate_low = tx
            print_log(f"[measure_mlffr] update mlffr = {tx}")
        else:
            rate_high = tx
    print_log(f"[measure_mlffr] return mlffr = {mlffr}")
    return mlffr

if __name__ == "__main__":
    _, _, CLIENT_DIR = read_machine_info_from_file(CONFIG_file_xl170)
    PKTGEN_PATH = f"{CLIENT_DIR}/dpdk-burst-replay/src/"
    pcap_file = "/data/local/qx51/dpdk-burst-replay/src/tmp/20flow_syn/max_64/xdp_token_bucket_shared_nothing_2.pcap"
    measure_time = 30
    rate_high = 30
    rate_low = 0.0
    precision = 1 # mpps
    measure_mlffr(pcap_file, measure_time, rate_high, rate_low, precision)
