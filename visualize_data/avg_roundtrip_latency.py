from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np

# x-axis: # of cores; y-axis: avg latency
PROG_FILE_NAME = "trex_stats.txt"
LATENCY_FILE_NAME = "avg_avg_roundtrip_latency.csv"
LATENCY_FILE_NAME_STDEV = "avg_avg_roundtrip_latency_stdev.csv"
LATENCY_FILE_NAME_EACH_RUN = "avg_roundtrip_latencycsv"
LATENCY_FILE_NAME_FIG = "avg_avg_roundtrip_latency.pdf"

# data in the input file: count,rx_pps,tx_pps,diff,max_l,min_l,avg_l
# rx/tx rate in the input file is pps
def latency_single_run(input_file):
    latency = 0
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return latency = 0")
        return 0
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(',')
        # print(f"{len(line)}, line: {line}")
        if len(line) < 7:
            continue
        latency = float(line[6])
        # print(f"latency: {latency}")
        if latency != 0:
            break
    f.close()
    if latency == 0:
        print(f"ERROR: no latency in {input_file}. Return latency = 0")
        return 0
    return latency

def latency_multiple_run(num_runs, input_folder, trex_stats_v):
    latency_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{trex_stats_v}/{PROG_FILE_NAME}"
        print(f"processing {input_file}")
        latency = latency_single_run(input_file)
        # print(f"{i}: {latency}")
        latency_list.append(latency)

    return latency_list

def write_latency_each_run(num_runs, num_cores_min, num_cores_max, latency_matrix, write_mode, version_name, output_folder):
    header = []
    for i in range(num_cores_min, num_cores_max + 1):
        for j in range(0, num_runs):
            header.append(f"{i} core(s), run {j}")
    data = []
    for x in latency_matrix:
        data.extend(x)
    output_file = f"{output_folder}/{LATENCY_FILE_NAME_EACH_RUN}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(data)
    f.close()

def write_avg_latency(num_cores_min, num_cores_max, latency_matrix, write_mode, version_name, output_folder):
    avg_latency_list = []
    for x in latency_matrix:
        avg = sum(x) / len(x)
        # print(f"avg = {avg}")
        avg_latency_list.append(avg)
    output_file = f"{output_folder}/{LATENCY_FILE_NAME}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    header = list(range(num_cores_min, num_cores_max + 1))
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(avg_latency_list)
    f.close()

    stdev_list = []
    for x in latency_matrix:
        sd = 0
        if len(x) > 1:
            sd = stdev(x)
        # print(f"stdev = {sd}")
        stdev_list.append(sd)
    output_file = f"{output_folder}/{LATENCY_FILE_NAME_STDEV}"
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
        line_new = [round(float(x), 2) for x in line]
        data.append(line_new)
    f.close()
    return data

def plot_progs_avg_latency(num_cores_min, num_cores_max, input_folder, prog_name, version_name_list, version_name_show_list,
    output_folder, trex_stats_version):
    # read Standard Deviation from csv file
    input_file = f"{input_folder}/{LATENCY_FILE_NAME_STDEV}"
    stdev_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of stdev in {input_file}. Stop plotting")
        return
    # read average latency from csv file
    input_file = f"{input_folder}/{LATENCY_FILE_NAME}"
    avg_latency_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of avg_latency_list in {input_file}. Stop plotting")
        return

    # plot the figure with error bar
    plt.figure()
    plt.title(f"{prog_name}  {trex_stats_version}")
    plt.xlabel("Number of cores")
    plt.ylabel("Average roundtrip latency (us)")
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    # plot a curve for each version
    for i, version_name in enumerate(version_name_list):
        print(f"version name: {version_name}")
        plt.plot(x, avg_latency_list[i], label=version_name_show_list[i])
        plt.errorbar(x, avg_latency_list[i], yerr=stdev_list[i], fmt='o', capsize=6)
    plt.legend()
    # plt.legend(loc='lower right')
    output_file = f"{output_folder}/{LATENCY_FILE_NAME_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file)

def visualize_prog_avg_latency_ns(prog_name, version_name_list, version_name_show_list,
    num_runs, num_cores_min, num_cores_max, input_folder, trex_stats_versions, output_folder):
    for trex_stats_v in trex_stats_versions:
        output_folder_v = f"{output_folder}/{trex_stats_v}"
        if not exists(output_folder_v):
            os.system(f"sudo mkdir -p {output_folder_v}")
        first_flag = True
        for version_name in version_name_list:
            latency_matrix = []
            for i in range(num_cores_min, num_cores_max + 1):
                latency_list = latency_multiple_run(num_runs, f"{input_folder}/{version_name}/{i}", trex_stats_v)
                latency_matrix.append(latency_list)
            if first_flag is True:
                write_mode = "w"
                first_flag = False
            else:
                write_mode = "a+"
            write_latency_each_run(num_runs, num_cores_min, num_cores_max, latency_matrix, write_mode, version_name, output_folder_v)
            write_avg_latency(num_cores_min, num_cores_max, latency_matrix, write_mode, version_name, output_folder_v)

        plot_progs_avg_latency(num_cores_min, num_cores_max, output_folder_v, prog_name, version_name_list, version_name_show_list,
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
    trex_stats_versions = ["no_profile", "prog_ns", "prog", "perf"]
    visualize_prog_avg_latency_ns(prog_name, version_name_list, version_name_show_list,
        num_runs, num_cores_min, num_cores_max, input_folder, trex_stats_versions, output_folder)
