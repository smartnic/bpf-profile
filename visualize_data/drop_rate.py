from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np

# x-axis: # of cores; y-axis: drop rate
PROG_FILE_NAME = "trex_stats.txt"
DROP_RATE_FILE_NAME = "avg_drop_rate.csv"
DROP_RATE_FILE_NAME_STDEV = "avg_drop_rate_stdev.csv"
DROP_RATE_FILE_NAME_EACH_RUN = "drop_rate.csv"
DROP_RATE_FILE_NAME_FIG = "avg_drop_rate.pdf"

# data in the input file: count,rx_pps,tx_pps,diff,max_l,min_l,avg_l
# drop rate in the input file is pps
def drop_rate_single_run(input_file):
    drop_rate = float("inf")
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return drop_rate = 0")
        return 0
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(',')
        # print(f"{len(line)}, line: {line}")
        if len(line) < 7:
            continue
        drop_rate = float(line[3]) / pow(10,6)
        # print(f"drop_rate: {drop_rate}")
    f.close()
    if drop_rate == float("inf"):
        print(f"ERROR: no drop_rate in {input_file}. Return drop_rate = 100")
        return 100
    return drop_rate

def drop_rate_multiple_run(num_runs, input_folder, trex_stats_v):
    drop_rate_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{trex_stats_v}/{PROG_FILE_NAME}"
        print(f"processing {input_file}")
        drop_rate = drop_rate_single_run(input_file)
        # print(f"{i}: {drop_rate}")
        drop_rate_list.append(drop_rate)

    return drop_rate_list

def write_drop_rate_each_run(num_runs, num_cores_min, num_cores_max, drop_rate_matrix, write_mode, version_name, output_folder):
    header = []
    for i in range(num_cores_min, num_cores_max + 1):
        for j in range(0, num_runs):
            header.append(f"{i} core(s), run {j}")
    data = []
    for x in drop_rate_matrix:
        data.extend(x)
    output_file = f"{output_folder}/{DROP_RATE_FILE_NAME_EACH_RUN}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(data)
    f.close()

def write_avg_drop_rate(num_cores_min, num_cores_max, drop_rate_matrix, write_mode, version_name, output_folder):
    avg_drop_rate_list = []
    for x in drop_rate_matrix:
        avg = sum(x) / len(x)
        # print(f"avg = {avg}")
        avg_drop_rate_list.append(avg)
    output_file = f"{output_folder}/{DROP_RATE_FILE_NAME}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    header = list(range(num_cores_min, num_cores_max + 1))
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(avg_drop_rate_list)
    f.close()

    stdev_list = []
    for x in drop_rate_matrix:
        sd = 0
        if len(x) > 1:
            sd = stdev(x)
        # print(f"stdev = {sd}")
        stdev_list.append(sd)
    output_file = f"{output_folder}/{DROP_RATE_FILE_NAME_STDEV}"
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

def plot_progs_avg_drop_rate(num_cores_min, num_cores_max, input_folder, prog_name, version_name_list, version_name_show_list,
    output_folder, trex_stats_version):
    # read Standard Deviation from csv file
    input_file = f"{input_folder}/{DROP_RATE_FILE_NAME_STDEV}"
    stdev_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of stdev in {input_file}. Stop plotting")
        return
    # read average drop_rate from csv file
    input_file = f"{input_folder}/{DROP_RATE_FILE_NAME}"
    avg_drop_rate_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of avg_drop_rate_list in {input_file}. Stop plotting")
        return

    # plot the figure with error bar
    plt.figure()
    plt.title(f"{prog_name}  {trex_stats_version}")
    plt.xlabel("Number of cores")
    plt.ylabel("Average drop rate (Mpps)")
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    # plot a curve for each version
    for i, version_name in enumerate(version_name_list):
        print(f"version name: {version_name}")
        plt.plot(x, avg_drop_rate_list[i], label=version_name_show_list[i])
        plt.errorbar(x, avg_drop_rate_list[i], yerr=stdev_list[i], fmt='o', capsize=6)
    plt.legend()
    # plt.legend(loc='lower right')
    output_file = f"{output_folder}/{DROP_RATE_FILE_NAME_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file)

def visualize_prog_avg_drop_rate_ns(prog_name, version_name_list, version_name_show_list,
    num_runs, num_cores_min, num_cores_max, input_folder, trex_stats_versions, output_folder):
    for trex_stats_v in trex_stats_versions:
        output_folder_v = f"{output_folder}/{trex_stats_v}"
        if not exists(output_folder_v):
            os.system(f"sudo mkdir -p {output_folder_v}")
        first_flag = True
        for version_name in version_name_list:
            drop_rate_matrix = []
            for i in range(num_cores_min, num_cores_max + 1):
                drop_rate_list = drop_rate_multiple_run(num_runs, f"{input_folder}/{version_name}/{i}", trex_stats_v)
                drop_rate_matrix.append(drop_rate_list)
            if first_flag is True:
                write_mode = "w"
                first_flag = False
            else:
                write_mode = "a+"
            write_drop_rate_each_run(num_runs, num_cores_min, num_cores_max, drop_rate_matrix, write_mode, version_name, output_folder_v)
            write_avg_drop_rate(num_cores_min, num_cores_max, drop_rate_matrix, write_mode, version_name, output_folder_v)

        plot_progs_avg_drop_rate(num_cores_min, num_cores_max, output_folder_v, prog_name, version_name_list, version_name_show_list,
            output_folder_v, trex_stats_v)

if __name__ == "__main__":
    input_folder = "../test1/10"
    output_folder = "../test1/10/graph"
    num_cores_min = 1
    num_cores_max = 8
    num_runs = 1
    prog_name = "xdp_portknock"
    version_name_list = ["v1", "v2"]
    version_name_show_list = ["shared state", "local state"]
    trex_stats_versions = ["", "prog_ns", "prog", "perf"]
    visualize_prog_avg_drop_rate_ns(prog_name, version_name_list, version_name_show_list,
        num_runs, num_cores_min, num_cores_max, input_folder, trex_stats_versions, output_folder)
