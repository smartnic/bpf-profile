from trex_stl_lib.api import *
import time
import argparse
import csv
from os.path import exists
import os
import numpy as np
import shutil

MEASUREMENT_START_FILE = "measure_start.txt"
MEASUREMENT_STOP_FILE = "measure_stop.txt"
MEASUREMENT_OUTPUT_FILE = "trex_stats.txt"
PKT_GEN_STABLE_FILE = "packet_gen_stable.txt"

def read_action_from_file(input_file):
    if not exists(input_file):
        return False, None
    output_path = None
    f = open(input_file, "r")
    for line in f:
        line = line.split()
        if len(line) < 1:
            continue
        output_path = line[0]
        break
    f.close()
    if output_path is None:
        return False, None
    os.remove(input_file)
    return True, output_path

def start_measure():
    action, output_path = read_action_from_file(MEASUREMENT_START_FILE)
    if action:
        if not exists(output_path):
            os.system(f"sudo mkdir -p {output_path}")
    return action, f"{output_path}/{MEASUREMENT_OUTPUT_FILE}"

def stop_measure():
    action, _ = read_action_from_file(MEASUREMENT_STOP_FILE)
    return action

def set_packet_gen_stable():
    print("set_packet_gen_stable")
    tmp_file = f"{PKT_GEN_STABLE_FILE}_tmp"
    f = open(f"{tmp_file}", "w")
    string = "yes" # content does not matter
    f.writelines(string)
    f.close()
    shutil.move(tmp_file, PKT_GEN_STABLE_FILE)

def check_packet_gen_stable():
    if exists(PKT_GEN_STABLE_FILE):
        os.remove(PKT_GEN_STABLE_FILE)
        return True
    else:
        return False

def send_packets(benchmark, version, dur, rate, num_cores, num_flows, base_pkt_len):
    if exists(PKT_GEN_STABLE_FILE):
        os.remove(PKT_GEN_STABLE_FILE)
    c = STLClient(server='127.0.0.1')
    # increase the tx rate a little bit so that the actual tx rate would be close to what we expect
    rate_to_trex = rate * 1.003
    print("rate_to_trex:", rate_to_trex)
    try:
        tx_port = 0
        rx_port = 0
        c.connect() # connect to server
        c.reset(ports = 0)
        c.add_profile(filename="stl/udp_for_benchmarks.py", ports=0,
            kwargs={"packet_len": base_pkt_len,
                    "stream_count": 1,
                    "benchmark": benchmark,
                    "version": version,
                    "num_cores": num_cores,
                    "num_flows": num_flows})
        # Need to specify 'force', or add the destination mac address in /etc/trex_cfg.yaml
        # otherwise, not able to send packets (cannot pass the start check)
        c.start(ports = 0, duration = dur, mult=f"{rate_to_trex}mpps", force=True)
        t_start = time.time()
        max_wait_time = 120.0
        time.sleep(10)
        t_wait_start = time.time()
        # wait until tx rate is stable
        tx_before = 0.0
        while True:
            wait_time = time.time() - t_wait_start
            if wait_time >= max_wait_time:
                break
            stats = c.get_stats()
            if tx_port not in stats:
                continue
            if "tx_pps" not in stats[tx_port]:
                continue
            tx_pps = stats[tx_port]["tx_pps"]
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
                break
            stats = c.get_stats()
            if rx_port not in stats:
                continue
            if "rx_pps" not in stats[rx_port]:
                continue
            rx_pps = stats[rx_port]["rx_pps"]
            if rx_pps > 0:
                variance = abs(rx_pps - rx_before) / rx_pps
                if variance < 0.01: # rx is stable
                    print(f"variance: {variance}, rx_pps: {rx_pps}")
                    break
                rx_before = rx_pps
            time.sleep(1)
        print(f"rx stabilize time: {time.time() - t_start}")
        set_packet_gen_stable()
        while True:
            time.sleep(0.5)
            # 1. check whether to start measuring every 0.5 second
            action, output_file = start_measure()
            while not action:
                action, output_file = start_measure()
                time.sleep(0.5)

            # 2. get statistics every 0.5 second
            print("Start measurement")
            rx_pps_list = []
            tx_pps_list = []
            rx_bps_list = []
            tx_bps_list = []
            min_l_list = []
            avg_l_list = []
            max_l_list = []
            count = 0
            while True:
                # 3. Check whether to stop measuring
                if stop_measure():
                    print("Stop measurement")
                    break
                stats = c.get_stats()
                if stats[tx_port]["tx_pps"] > 0:
                    rx_pps_list.append(stats[rx_port]["rx_pps"])
                    tx_pps_list.append(stats[tx_port]["tx_pps"])
                    rx_bps_list.append(stats[rx_port]["rx_bps"])
                    tx_bps_list.append(stats[tx_port]["tx_bps"])
                    # latency_stats = stats["latency"][2]["latency"]
                    # min_l_list.append(latency_stats["total_min"])
                    # max_l_list.append(latency_stats["total_max"])
                    # avg_l_list.append(latency_stats["average"])
                    # print(stats[rx_port]["rx_pps"], stats[tx_port]["tx_pps"],
                    #       stats[rx_port]["rx_bps"], stats[tx_port]["tx_bps"])
                    count += 1
                    time.sleep(0.5)
                # mode = 'a'
                # debug_count += 1
                # if debug_count == 1:
                #     mode = 'w'
                # f = open(f"{output_file}.debug", mode)
                # writer = csv.writer(f)
                # lst = [expected_actual_rate, stats[rx_port]["rx_pps"], stats[tx_port]["tx_pps"]]
                # writer.writerow(lst)
                # f.close()
            # 4. Store statistics in the file
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
            print(f"maxL = {max_l}")
            print(f"minL = {min_l}")
            print(f"avgL = {avg_l}")
            print(f"rx_bps = {rx_bps}")
            print(f"tx_bps = {tx_bps}")
            f = open(output_file, 'w')
            writer = csv.writer(f)
            lst = [count, rx_pps, tx_pps, diff, max_l, min_l, avg_l, rx_bps, tx_bps, diff_bps]
            writer.writerow(lst)
            f.close()
    except STLError as e:
        print(e)

    finally:
        c.disconnect()
        time.sleep(10)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-b', dest="benchmark", type=str, help='Name of the BPF program', required=True)
    parser.add_argument('-v', dest="version", type=str, help='Name of version (e.g v1, v2, v3)', required=True)
    parser.add_argument('-t', dest="time", type=int, help='How long(secs) you want to send packets', default=100)
    parser.add_argument('-r', dest="rate", type=float, help='Multiplier send rate in Mpps', default=1)
    parser.add_argument('-nc', dest="num_cores", type=int, help='Number of cores', required=True)
    parser.add_argument('-nf', dest="num_flows", type=int, help='Number of flows', required=True)
    parser.add_argument('-l', dest="base_pkt_len", type=int, help='base packet len (>=64)', required=True)
    args = parser.parse_args()
    send_packets(args.benchmark, args.version, args.time, args.rate,
        args.num_cores, args.num_flows, args.base_pkt_len)
