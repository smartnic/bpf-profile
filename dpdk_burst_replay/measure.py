import time
import subprocess
import argparse
import csv
from os.path import exists
import os
import numpy as np
from statistics import stdev

OUTPUT_FILE = "pktgen_stats.txt"

def run_cmd(cmd, wait=True):
    # print(cmd)
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
    get_stats_cmd = f"bash eth_stat.sh ens114np0 {stats_file}"
    run_cmd(get_stats_cmd) # block until get stats
    if not exists(stats_file):
        print(f"ERROR: no such file {stats_file}.")
        return None
    stats_list = {}
    f = open(stats_file, "r")
    for line in f:
        str_list = line.split()
        if len(str_list) < 2:
            return None
        stats_list["rx_pps"] = float(str_list[0])
        stats_list["tx_pps"] = float(str_list[1])
        stats_list["rx_bps"] = 0
        stats_list["tx_bps"] = 0
    f.close()
    print(stats_list)
    run_cmd(f"rm -f {stats_file}")
    return stats_list

def wait_until_packet_gen_stable(timeout):
    t_start = time.time()
    max_wait_time = float(timeout)
    time.sleep(2)
    t_wait_start = time.time()
    # wait until tx rate is stable
    tx_before = 0.0
    while True:
        wait_time = time.time() - t_wait_start
        if wait_time >= max_wait_time:
            return False
        stats = get_stats()
        if "tx_pps" not in stats:
            continue
        tx_pps = stats["tx_pps"]
        if tx_pps > 0:
            variance = abs(tx_pps - tx_before) / tx_pps
            if variance < 0.01: # tx is stable
                print(f"variance: {variance}, tx_pps: {tx_pps}")
                tx_before = tx_pps
                break
            tx_before = tx_pps
        time.sleep(1)
    print(f"tx stabilize time: {time.time() - t_start}")
    # wait until rx rate is stable
    rx_before = 0.0
    t_start = time.time()
    while True:
        wait_time = time.time() - t_wait_start
        if wait_time >= max_wait_time:
            return False
        stats = get_stats()
        if "rx_pps" not in stats:
            continue
        rx_pps = stats["rx_pps"]
        if rx_pps == rx_before:
            break
        if rx_pps > 0:
            variance = abs(rx_pps - rx_before) / rx_pps
            if variance < 0.01: # rx is stable
                print(f"variance: {variance}, rx_pps: {rx_pps}")
                break
            rx_before = rx_pps
        time.sleep(1)
    print(f"rx stabilize time: {time.time() - t_start}")
    return True

def measure_performance(duration, output_folder):
    run_cmd("mkdir -p " + output_folder, wait=True)
    output_file = f"{output_folder}/{OUTPUT_FILE}"
    # 1. get statistics every 0.5 second
    print("Start measurement")
    rx_pps_list = []
    tx_pps_list = []
    rx_bps_list = []
    tx_bps_list = []
    min_l_list = []
    avg_l_list = []
    max_l_list = []
    count = 0
    t_start = time.time()
    while True:
        # 2. Check whether to stop measuring
        if time.time() - t_start > duration:
            print("Stop measurement")
            break
        stats = get_stats()
        if stats["tx_pps"] > 0:
            rx_pps_list.append(stats["rx_pps"])
            tx_pps_list.append(stats["tx_pps"])
            rx_bps_list.append(stats["rx_bps"])
            tx_bps_list.append(stats["tx_bps"])
            count += 1
            time.sleep(0.5)
        # mode = 'a'
        # debug_count += 1
        # if debug_count == 1:
        #     mode = 'w'
        # f = open(f"{output_file}.debug", mode)
        # writer = csv.writer(f)
        # lst = [expected_actual_rate, stats["rx_pps"], stats["tx_pps"]]
        # writer.writerow(lst)
        # f.close()
    # 3. Store statistics in the file
    print("rx_pps_list: ", rx_pps_list)
    print("tx_pps_list: ", tx_pps_list)
    rx_pps = np.mean(rx_pps_list)
    tx_pps = np.mean(tx_pps_list)
    diff = np.mean(np.abs(np.subtract(rx_pps_list, tx_pps_list)))
    max_l = 0
    min_l = 0
    avg_l = 0
    print("rx_bps_list: ", rx_bps_list)
    print("tx_bps_list: ", tx_bps_list)
    rx_bps = np.mean(rx_bps_list)
    tx_bps = np.mean(tx_bps_list)
    diff_bps = np.mean(np.abs(np.subtract(rx_bps_list, tx_bps_list)))
    print(f"rx = {rx_pps}")
    print(f"tx = {tx_pps}")
    print(f"diff = {diff}")
    print(f"rx_bps = {rx_bps}")
    print(f"tx_bps = {tx_bps}")
    f = open(output_file, 'w')
    writer = csv.writer(f)
    lst = [count, rx_pps, tx_pps, diff, max_l, min_l, avg_l, rx_bps, tx_bps, diff_bps]
    writer.writerow(lst)
    stdev_list = []
    if count > 0:
        stdev_list = [stdev(rx_pps_list), stdev(tx_pps_list),
                      0, 0, 0,
                      stdev(rx_bps_list), stdev(tx_bps_list)]
    writer.writerow(stdev_list)
    writer.writerow(rx_pps_list)
    writer.writerow(tx_pps_list)
    writer.writerow(min_l_list)
    writer.writerow(avg_l_list)
    writer.writerow(max_l_list)
    writer.writerow(rx_bps_list)
    writer.writerow(tx_bps_list)
    f.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-t', dest="time", type=int, help='How long(secs) you want to measure performance', default=30)
    parser.add_argument('-o', dest="output_folder", type=str, help='output_folder', required=True)
    args = parser.parse_args()
    # wait_until_packet_gen_stable()
    measure_performance(args.time, args.output_folder)
