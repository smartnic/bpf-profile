from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np

# input file. program level raw data from bpftool when kernel bpf stats is enabled
PROG_FILE_NAME = "prog_ns.txt"
LATENCY_FILE_NAME = "avg_latency_ns.csv"
LATENCY_FILE_NAME_STDEV = "avg_latency_ns_stdev.csv"
LATENCY_FILE_NAME_EACH_RUN = "latency_ns.csv"
LATENCY_FILE_NAME_FIG = "avg_latency_ns.pdf"

def latency_single_run(input_file):
    run_cnt = 0
    run_time_ns = 0
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return latency = 0")
        return 0
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split()
        if len(line) < 11:
            continue
        run_time_ns = int(line[8])
        run_cnt = int(line[10])
        if run_cnt != 0 and run_time_ns != 0:
            break
    f.close()
    if run_cnt == 0:
        print(f"ERROR: no run_cnt in {input_file}. Return latency = 0")
        return 0
    if run_time_ns == 0:
        print(f"ERROR: no run_time_ns in {input_file}. Return latency = 0")
        return 0
    return (run_time_ns / run_cnt)

def latency_multiple_run(num_runs, input_folder):
    latency_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{PROG_FILE_NAME}"
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
        line_new = [float(x) for x in line]
        data.append(line_new)
    f.close()
    return data

def plot_progs_avg_latency(num_cores_min, num_cores_max, input_folder, prog_name, version_name_list, output_folder):
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
    plt.title(prog_name)
    plt.xlabel("Number of cores")
    plt.ylabel("Average latency (nanoseconds)")
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    # plot a curve for each version
    for i, version_name in enumerate(version_name_list):
        print(f"version name: {version_name}")
        plt.plot(x, avg_latency_list[i], label=version_name)
        plt.errorbar(x, avg_latency_list[i], yerr=stdev_list[i], fmt='o', capsize=6)
    plt.legend(loc='lower right')
    output_file = f"{output_folder}/{LATENCY_FILE_NAME_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file)

def visualize_prog_avg_latency_ns(prog_name, version_name_list, num_runs, num_cores_min, num_cores_max, input_folder, output_folder):
    if not exists(output_folder):
        os.system(f"sudo mkdir -p {output_folder}")
    first_flag = True
    for version_name in version_name_list:
        latency_matrix = []
        for i in range(num_cores_min, num_cores_max + 1):
            latency_list = latency_multiple_run(num_runs, f"{input_folder}/{version_name}/{i}")
            latency_matrix.append(latency_list)
        if first_flag is True:
            write_mode = "w"
            first_flag = False
        else:
            write_mode = "a+"
        write_latency_each_run(num_runs, num_cores_min, num_cores_max, latency_matrix, write_mode, version_name, output_folder)
        write_avg_latency(num_cores_min, num_cores_max, latency_matrix, write_mode, version_name, output_folder)

    plot_progs_avg_latency(num_cores_min, num_cores_max, output_folder, prog_name, version_name_list, output_folder)

if __name__ == "__main__":
    input_folder = "/mydata/test3/xdpex1"
    output_folder = "/mydata/test3/xdpex1/analyze_v2"
    num_cores_min = 1
    num_cores_max = 8
    num_runs = 5
    prog_name = "xdpex1"
    version_name_list = ["v2"]
    visualize_prog_avg_latency_ns(prog_name, version_name_list, num_runs, num_cores_min, num_cores_max, input_folder, output_folder)