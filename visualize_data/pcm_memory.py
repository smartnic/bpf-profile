from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np

PROG_FILE_NAME = "pcm_memory.csv" # input file. program level raw data from bpftool
PCM_OUTPUT = "avg_pcm_memory_system_read.csv"
PCM_OUTPUT_STDEV = "avg_memory_system_read_stdev.csv"
PCM_OUTPUT_EACH_RUN = "pcm_memory_system_read.csv"
PCM_OUTPUT_FIG = "pcm_memory_system_read.pdf"

# metric value is the AVERAGE metric value of all valid cores
def metric_single_run(input_file, metric_keyword):
    metric = 0
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return metric = 0")
        return 0
    f = open(input_file, "r")
    system_keyword = "System"
    id_metric = None
    line_count = 0
    line_0 = None
    for line in f:
        line = line.strip().split(',')
        line = [x.strip() for x in line]
        if line_count == 0:
            line_0 = line
        elif line_count == 1:
            for i, x in enumerate(line):
                if x == metric_keyword and line_0[i] == system_keyword:
                    # print(i, line_0[i], x)
                    id_metric = i
                    break
        elif line_count == 2:
            if id_metric is None:
                print(f"ERROR: no System {metric_keyword} metric in {input_file}. Return metric = 0")
                return 0
            metric = float(line[i])
            break
        line_count += 1
    f.close()
    return metric

def metric_multiple_run(num_runs, input_folder, metric_keyword):
    metric_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{PROG_FILE_NAME}"
        print(f"processing {input_file}")
        metric = metric_single_run(input_file, metric_keyword)
        # print(f"{i}: {metric}")
        metric_list.append(metric)

    return metric_list

def write_metric_each_run(num_runs, num_cores_min, num_cores_max, metric_matrix, write_mode, version_name, output_folder):
    header = []
    for i in range(num_cores_min, num_cores_max + 1):
        for j in range(0, num_runs):
            header.append(f"{i} core(s), run {j}")
    data = []
    for x in metric_matrix:
        data.extend(x)
    output_file = f"{output_folder}/{PCM_OUTPUT_EACH_RUN}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(data)
    f.close()

def write_avg_metric(num_cores_min, num_cores_max, metric_matrix, write_mode, version_name, output_folder):
    avg_metric_list = []
    for x in metric_matrix:
        avg = sum(x) / len(x)
        # print(f"avg = {avg}")
        avg_metric_list.append(avg)
    output_file = f"{output_folder}/{PCM_OUTPUT}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    header = list(range(num_cores_min, num_cores_max + 1))
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(avg_metric_list)
    f.close()

    stdev_list = []
    for x in metric_matrix:
        sd = 0
        if len(x) > 1:
            sd = stdev(x)
        # print(f"stdev = {sd}")
        stdev_list.append(sd)
    output_file = f"{output_folder}/{PCM_OUTPUT_STDEV}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    header = list(range(num_cores_min, num_cores_max + 1))
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(stdev_list)
    f.close()

def read_data_from_csv_file(input_file):
    data = []
    f = open(input_file, "r")
    csv_reader = csv.reader(f, delimiter=',')
    head_flag = True
    for line in csv_reader:
        if head_flag is True:
            head_flag = False
            continue
        line_new = [float(x) for x in line]
        data.append(line_new)
    f.close()
    return data

def plot_progs_avg_metric(metric_show, num_cores_min, num_cores_max, input_folder, prog_name, version_name_list,
    version_name_show_list, output_folder):
    # read Standard Deviation from csv file
    input_file = f"{input_folder}/{PCM_OUTPUT_STDEV}"
    stdev_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of stdev in {input_file}. Stop plotting")
        return
    # read average metric from csv file
    input_file = f"{input_folder}/{PCM_OUTPUT}"
    avg_metric_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of avg_metric_list in {input_file}. Stop plotting")
        return

    # plot the figure with error bar
    plt.figure()
    plt.title(prog_name)
    plt.xlabel("Number of cores")
    plt.ylabel(f"Average {metric_show}")
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    # plot a curve for each version
    for i, version_name in enumerate(version_name_list):
        print(f"version name: {version_name}")
        plt.plot(x, avg_metric_list[i], label=version_name_show_list[i])
        plt.errorbar(x, avg_metric_list[i], yerr=stdev_list[i], fmt='o', capsize=6)
    plt.legend()
    output_file = f"{output_folder}/{PCM_OUTPUT_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file)

def visualize_prog_avg_metric(metric_keyword, metric_show, prog_name, version_name_list, version_name_show_list, num_runs,
    num_cores_min, num_cores_max, input_folder, output_folder):
    print(f"Visualizing {metric_keyword}")
    if not exists(output_folder):
        os.system(f"sudo mkdir -p {output_folder}")
    first_flag = True
    for version_name in version_name_list:
        metric_matrix = []
        for i in range(num_cores_min, num_cores_max + 1):
            metric_list = metric_multiple_run(num_runs, f"{input_folder}/{version_name}/{i}", metric_keyword)
            metric_matrix.append(metric_list)
        if first_flag is True:
            write_mode = "w"
            first_flag = False
        else:
            write_mode = "a+"
        write_metric_each_run(num_runs, num_cores_min, num_cores_max, metric_matrix, write_mode, version_name, output_folder)
        write_avg_metric(num_cores_min, num_cores_max, metric_matrix, write_mode, version_name, output_folder)

    plot_progs_avg_metric(metric_show, num_cores_min, num_cores_max, output_folder, prog_name, version_name_list,
        version_name_show_list, output_folder)

def visualize_pcm_memory_metrics(metric_list, metric_show_list, prog_name, version_name_list, 
    version_name_show_list, num_runs, num_cores_min, num_cores_max, input_folder, output_folder):
    global PCM_OUTPUT, PCM_OUTPUT_STDEV, PCM_OUTPUT_EACH_RUN, PCM_OUTPUT_FIG
    for i, metric in enumerate(metric_list):
        PCM_OUTPUT = f"avg_pcm_memory_system_{metric}.csv"
        PCM_OUTPUT_STDEV = f"avg_pcm_memory_system_{metric}_stdev.csv"
        PCM_OUTPUT_EACH_RUN = f"pcm_memory_system_{metric}.csv"
        PCM_OUTPUT_FIG = f"pcm_memory_system_{metric}.pdf"
        visualize_prog_avg_metric(metric, metric_show_list[i], prog_name, version_name_list,
            version_name_show_list, num_runs, num_cores_min, num_cores_max, input_folder, output_folder)


if __name__ == "__main__":
    for x in ['1', '5', '10', '20', '37']:
        input_folder = f"../../pcm/xdp_portknock_xl170_3runs_60s_71ac472/dut/{x}/"
        output_folder = f"../../pcm/xdp_portknock_xl170_3runs_60s_71ac472/dut/graph/{x}/"
        num_cores_min = 1
        num_cores_max = 8
        num_runs = 3
        prog_name = "xdp_portknock"
        version_name_list = ["v1", "v2"]
        version_name_show_list = ["shared state", "local state"]
        metric_show_list = ["Read (MB/s)", "Write (MB/s)"]
        metric_list = ["Read", "Write"]
        visualize_pcm_memory_metrics(metric_list, metric_show_list, prog_name, version_name_list,
            version_name_show_list, num_runs, num_cores_min, num_cores_max, input_folder, output_folder)
