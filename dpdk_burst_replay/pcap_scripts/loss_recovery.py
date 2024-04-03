import yaml
import multiprocessing
import time
import os
import argparse
from loss_recovery_remove_pkts import remove_packets

BM_portknock = "portknock"

class WorkItem():
    def __init__(self):
        self.input_file = None
        self.output = None
        self.num_cores = None
        self.benchmark = None
        self.loss_rate = None

    def __str__(self):
        res = f"input_file: {self.input_file}\n"
        res += f"output: {self.output}\n"
        res += f"benchmark: {self.benchmark}\n"
        res += f"num_cores: {self.num_cores}\n"
        res += f"loss_rate: {self.loss_rate}\n"
        return res

    def __copy__(self):
        x = WorkItem()
        x.input_file = self.input_file
        x.output = self.output
        x.benchmark = self.benchmark
        x.num_cores = self.num_cores
        x.loss_rate = self.loss_rate
        return x


def read_args_from_yaml(yaml_file):
    # Read the YAML file
    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)
    item_list = []
    # Process the data
    for x in data.get("items", []):
        loss_rate_list = []
        if x.get("loss_rate_list"):
            loss_rate_list = str(x.get("loss_rate_list")).split(",")
            loss_rate_list = [l.strip() for l in loss_rate_list]
        item = WorkItem()
        item.input_file = x.get("input")
        item.output = x.get("output")
        item.num_cores = int(x.get("num_cores"))
        item.benchmark = x.get("benchmark")
        for l in loss_rate_list:
            new_item = item.__copy__()
            new_item.output += f"/{l}/"
            new_item.loss_rate = l
            item_list.append(new_item)
    print("Work item list:")
    for x in item_list:
        print(x)
    return item_list


def add_tasks_to_process_pool(num_cores, output_path, input_path, benchmark, loss_rate):
    sleep_dur = 0.1
    print(f"[add_tasks_to_process_pool] {benchmark} {input_path} {output_path} {num_cores} {loss_rate}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    result_list = []
    num_first_pkts_left = 1024
    num_last_pkts_left = num_first_pkts_left
    if benchmark == BM_portknock:
        for n in range(1, num_cores + 1):
            name = f"xdp_portknock_shared_nothing_pkt_loss_{n}.pcap"
            input_file = f"{input_path}/{name}"
            output_file = f"{output_path}/{name}"
            r = pool.apply_async(remove_packets,
                                 args=(input_file, output_file, num_first_pkts_left, num_last_pkts_left, loss_rate))
            result_list.append(r)
            time.sleep(sleep_dur)
    return result_list


if __name__ == "__main__":
    # Path to your YAML file
    parser = argparse.ArgumentParser(description='Information about parameters')
    parser.add_argument('--config', '-c', dest='config_file', help='Config file name', required=True)
    args = parser.parse_args()
    item_list = read_args_from_yaml(args.config_file)
    t_start = time.time()
    n_processes = 27
    sleep_dur = 0.1
    # Create n_processes multiprocessing Pools, one for each function
    with multiprocessing.Pool(processes=n_processes) as pool:
        result_list = []
        for item in item_list:
            input_path = item.input_file
            output_path = item.output
            num_cores = item.num_cores
            benchmark = item.benchmark
            loss_rate = item.loss_rate
            result_list += add_tasks_to_process_pool(num_cores, output_path, input_path, 
                                                     benchmark, loss_rate)

        # Wait for subprocesses to complete
        print(f"# of tasks: {len(result_list)}")
        c = 1
        for r in result_list:
            r.wait()
            print(f"task {c} completes")
            c += 1

    print(f"pcap time_cost: {time.time() - t_start}")
    print(f"time_cost: {time.time() - t_start}")
