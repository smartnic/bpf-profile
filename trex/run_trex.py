from trex_stl_lib.api import *
import time
import argparse
import csv
from os.path import exists
import os

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
    os.remove(input_file)
    if output_path is None:
        print(f"ERROR: no output path in {input_file}. Return False, None")
        return False, None
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
            # 1. check whether to start measuring
            action, output_file = start_measure()
            while not action:
                action, output_file = start_measure()
                time.sleep(0.5)

            # 2. get statistics and store in a file every 0.5 second
            expected_actual_rate = (rate-rate*0.01) * pow(10,6)
            print("Start measurement")
            print(f"Expected actual rate: {expected_actual_rate}")
            rx_pps = []
            tx_pps = []
            min_l = []
            avg_l = []
            max_l = []
            count = 1
            while True:
                if stop_measure():
                    print("Stop measurement")
                    break
                stats = c.get_stats()
                if stats[tx_port]["tx_pps"] >= expected_actual_rate:
                    rx_pps.append(stats[rx_port]["rx_pps"])
                    tx_pps.append(stats[tx_port]["tx_pps"])
                    latency_stats = stats["latency"][2]["latency"]
                    min_l.append(latency_stats["total_min"])
                    max_l.append(latency_stats["total_max"])
                    avg_l.append(latency_stats["average"])
                    write_mode = 'w'
                    f = open(output_file, write_mode)
                    writer = csv.writer(f)
                    lst = [rx_pps, tx_pps, latency_stats, min_l, max_l, avg_l]
                    writer.writerow(rx_pps)
                    writer.writerow(tx_pps)
                    writer.writerow(latency_stats)
                    writer.writerow(min_l)
                    writer.writerow(avg_l)
                    f.close()
                    print(count)
                    print(rx_pps)
                    print(tx_pps)
                    count += 1
                    time.sleep(0.5)
    except STLError as e:
        print(e)

    finally:
        c.disconnect()
        time.sleep(10)
