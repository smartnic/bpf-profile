from trex_stl_lib.api import *
import time
import argparse
import csv
from os.path import exists
import os
import numpy as np

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

def measure_rx(rate, measure_time, benchmark, version, num_cores, num_flows):
    rx = 0
    # increase the tx rate a little bit so that the actual tx rate would be close to what we expect
    rate_to_trex = rate * 1.003
    print("rate_to_trex:", rate_to_trex)
    c = STLClient(server='127.0.0.1')
    try:
        tx_port = 0
        rx_port = 0
        c.connect() # connect to server
        c.reset(ports = 0)
        c.add_profile(filename="stl/udp_for_benchmarks.py", ports=0,
            kwargs={"packet_len": 64,
                    "stream_count": 1,
                    "benchmark": benchmark,
                    "version": version,
                    "num_cores": num_cores,
                    "num_flows": num_flows})
        # Need to specify 'force', or add the destination mac address in /etc/trex_cfg.yaml
        # otherwise, not able to send packets (cannot pass the start check)
        # Set duration as 10000 seconds (assume it is long enough to measure rx, 
        # i.e., duration >> measure_time)
        c.start(ports = 0, duration = 10000, mult=f"{rate_to_trex}mpps", force=True)
        # waiting until tx/rx rates are stable
        t_wait_start = time.time()
        max_wait_time = 120.0
        rx_before = 0.0
        expected_actual_rate = (rate-rate*0.01) * pow(10,6)
        if expected_actual_rate >= 37.2 * pow(10,6):
            expected_actual_rate = 37 * pow(10,6)
        print(f"Expected actual rate: {expected_actual_rate} pps, rate: {rate} mpps")

        print("Wait for measurement......")
        # time.sleep(max_wait_time)
        time.sleep(10)
        # while True:
        #     time.sleep(1)
        #     wait_time = time.time() - t_wait_start
        #     if wait_time >= max_wait_time:
        #         break
        #     stats = c.get_stats()
        #     if tx_port not in stats:
        #         continue
        #     if "tx_pps" not in stats[tx_port]:
        #         continue
        #     tx_pps = stats[tx_port]["tx_pps"]
        #     # todo: check both the lower and upper bound
        #     if stats[tx_port]["tx_pps"] >= expected_actual_rate:
        #         rx_current = stats[rx_port]["rx_pps"]
        #         variance = abs(rx_current - rx_before) / rx_current
        #         if variance < 0.01: # rx is stable
        #             print(f"variance: {variance}, rx_current: {rx_current}")
        #             break
        #         rx_before = rx_current
        print("Start measurement......")
        t_start = time.time()
        # 1. get statistics every 0.5 second
        rx_pps_list = []
        count = 0
        while True:
            # 2. Check whether to stop measuring
            dur = time.time() - t_start
            if dur >= measure_time:
                print("Stop measurement")
                break
            time.sleep(0.5)
            stats = c.get_stats()
            print(f"\nbefore:\n{stats}")
            stats = c.get_stats()
            print(f"\nafter:\n{stats}")
            if tx_port not in stats:
                continue
            if "tx_pps" not in stats[tx_port]:
                continue
            if stats[tx_port]["tx_pps"] >= expected_actual_rate:
                if "rx_pps" not in stats[tx_port]:
                    continue
                rx_pps_list.append(stats[rx_port]["rx_pps"])
                count += 1
        # 3. Return rx rate
        rx_pps = np.mean(rx_pps_list)
        print(f"rx = {rx_pps}, count = {count}")
        rx = rx_pps
    except STLError as e:
        print(e)

    finally:
        c.disconnect()
        time.sleep(10)
        return (rx / pow(10,6))

def measure_mlffr(benchmark, version, num_cores, num_flows, 
                  measure_time, rate_high, rate_low, precision):
    print(f"measure mlffr: {benchmark}, {version}")
    print(f"num_cores: {num_cores}, num_flows: {num_flows}, measure_time: {measure_time} sec")
    print(f"{rate_low} mpps - {rate_high} mpps, precision: {precision} mpps")
    threshold = 0.04 # if (tx - rx) / tx <= threshold, update mlffr
    # set the initial value for mlffr
    mlffr = 0.0
    if rate_high < rate_low:
        print("[measure_mlffr] error: rate_high < rate_low")
        return mlffr
    if rate_high < 0 or rate_low < 0:
        print("[measure_mlffr] error: rate_high and rate_low should > 0")
        return mlffr
    while True:
        print(f"\n[measure_mlffr] rate_low = {rate_low}, rate_high = {rate_high}")
        # 1. check whether (rate_high - rate_low) < precision
        if (rate_high - rate_low) < precision:
            break
        # 2. measure rx under tx
        tx = (rate_high + rate_low) / 2
        print(f"[measure_mlffr] tx = {tx}")
        rx = measure_rx(tx, measure_time, benchmark, version, num_cores, num_flows)
        delta = (tx - rx) / tx
        print(f"[measure_mlffr] rx = {rx}, tx = {tx}, delta = {delta}")
        if delta <= threshold:
            mlffr = tx
            rate_low = tx
            print(f"[measure_mlffr] update mlffr = {tx}")
        else:
            rate_high = tx
    print(f"[measure_mlffr] return mlffr = {mlffr}")
    return mlffr

if __name__ == "__main__":
    benchmark = "portknock"
    version = "v2"
    num_cores = 2
    num_flows = 1
    measure_time = 30
    # record the highest rate that trex can generate for each benchmark
    # add a function to auto get the highest tx that trex can generate
    # log_2^(27.2/0.1) = 9 
    rate_high = 27.2 # mpps for 8 cores (full header)
    rate_low = 0.0
    precision = 0.1 # mpps
    for _ in range(3):
        measure_mlffr(benchmark, version, num_cores, num_flows, 
                      measure_time, rate_high, rate_low, precision)
