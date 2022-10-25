from trex_stl_lib.api import *
import time
import argparse
import csv
from os.path import exists
import os
import numpy as np

MEASUREMENT_START_FILE = "measure_start.txt"
MEASUREMENT_STOP_FILE = "measure_stop.txt"
MEASUREMENT_OUTPUT_FILE = "trex_stats.txt"

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-b', dest="benchmark", type=str, help='Name of the BPF program', required=True)
    parser.add_argument('-v', dest="version", type=str, help='Name of version (e.g v1, v2, v3)', required=True)
    parser.add_argument('-t', dest="time", type=int, help='How long(secs) you want to send packets', default=100)
    parser.add_argument('-r', dest="rate", type=float, help='Multiplier send rate in Mpps', default=1)
    parser.add_argument('-nc', dest="num_cores", type=int, help='Number of cores', required=True)
    args = parser.parse_args()

    c = STLClient(server='127.0.0.1')
    rate = args.rate
    # increase the tx rate a little bit so that the actual tx rate would be close to what we expect
    rate_to_trex = rate * 1.003
    print("rate_to_trex:", rate_to_trex)
    try:
        tx_port = 0
        rx_port = 0
        c.connect() # connect to server
        c.reset(ports = 0)
        c.add_profile(filename="stl/udp_for_benchmarks.py", ports=0,
            kwargs={"packet_len": 64,
                    "stream_count": 1,
                    "benchmark": args.benchmark,
                    "version": args.version,
                    "num_cores": args.num_cores})
        # Need to specify 'force', or add the destination mac address in /etc/trex_cfg.yaml
        # otherwise, not able to send packets (cannot pass the start check)
        c.start(ports = 0, duration = args.time, mult=f"{rate_to_trex}mpps", force=True)
        time.sleep(1)

        while True:
            time.sleep(0.5)
            # 1. check whether to start measuring every 0.5 second
            action, output_file = start_measure()
            while not action:
                action, output_file = start_measure()
                time.sleep(0.5)

            # 2. get statistics every 0.5 second
            expected_actual_rate = (rate-rate*0.01) * pow(10,6)
            print("Start measurement")
            print(f"Expected actual rate: {expected_actual_rate}")
            rx_pps_list = []
            tx_pps_list = []
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
                if stats[tx_port]["tx_pps"] >= expected_actual_rate:
                    rx_pps_list.append(stats[rx_port]["rx_pps"])
                    tx_pps_list.append(stats[tx_port]["tx_pps"])
                    latency_stats = stats["latency"][2]["latency"]
                    min_l_list.append(latency_stats["total_min"])
                    max_l_list.append(latency_stats["total_max"])
                    avg_l_list.append(latency_stats["average"])
                    # print(rx_pps)
                    # print(tx_pps)
                    count += 1
                    time.sleep(0.5)
            # 4. Store statistics in the file
            print("rx_pps_list: ", rx_pps_list)
            print("tx_pps_list: ", tx_pps_list)
            rx_pps = np.mean(rx_pps_list)
            tx_pps = np.mean(tx_pps_list)
            diff = np.mean(np.abs(np.subtract(rx_pps_list, tx_pps_list)))
            max_l = np.mean(max_l_list)
            min_l = np.mean(min_l_list)
            avg_l = np.mean(avg_l_list)
            print(f"rx = {rx_pps}")
            print(f"tx = {tx_pps}")
            print(f"diff = {diff}")
            print(f"maxL = {max_l}")
            print(f"minL = {min_l}")
            print(f"avgL = {avg_l}")
            f = open(output_file, 'w')
            writer = csv.writer(f)
            lst = [count, rx_pps, tx_pps, diff, max_l, min_l, avg_l]
            writer.writerow(lst)
            f.close()
    except STLError as e:
        print(e)

    finally:
        c.disconnect()
        time.sleep(10)
