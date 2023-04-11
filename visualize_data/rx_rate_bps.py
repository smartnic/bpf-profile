from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np
import matplotlib

# x-axis: # of cores; y-axis: rx rate
PROG_FILE_NAME = "trex_stats.txt"
RX_RATE_FILE_NAME = "avg_rx_rate_bps.csv"
RX_RATE_FILE_NAME_STDEV = "avg_rx_rate_bps_stdev.csv"
RX_RATE_FILE_NAME_EACH_RUN = "rx_rate_bps.csv"
RX_RATE_FILE_NAME_FIG = "avg_rx_rate_bps.pdf"
EXTRA_HEADER_SIZE = 0
MD_ELEM_SIZE = 0

# data in the input file: count,rx_pps,tx_pps,diff,max_l,min_l,avg_l,rx_bps,tx_bps,diff_bps
def rx_rate_single_run(input_file, num_cores):
    rx_pps = 0
    rx_bps = 0
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return rx_rate = 0")
        return 0
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(',')
        # print(f"{len(line)}, line: {line}")
        if len(line) < 10:
            continue
        rx_pps = float(line[1])
        rx_bps = float(line[7])
        if rx_bps != 0 and rx_bps != 0:
            break
    f.close()
    if rx_pps == 0 or rx_bps == 0:
        print(f"ERROR: no rx_pps, rx_bps in {input_file}. Return rx_rate = 0")
        return 0
    metadata_size = MD_ELEM_SIZE * (num_cores - 1)
    x = EXTRA_HEADER_SIZE + metadata_size
    pkt_size = (rx_bps / (8 * rx_pps)) - x
    rx_rate_gbps = pkt_size * 8 * rx_pps / pow(10, 9)
    print(f"pkt_size: {pkt_size}, rx_rate_gbps: {rx_rate_gbps}")
    return rx_rate_gbps

def rx_rate_multiple_run(num_runs, input_folder, trex_stats_v, num_cores):
    rx_rate_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{trex_stats_v}/{PROG_FILE_NAME}"
        print(f"processing {input_file}")
        rx_rate = rx_rate_single_run(input_file, num_cores)
        # print(f"{i}: {rx_rate}")
        rx_rate_list.append(rx_rate)

    return rx_rate_list

def write_rx_rate_each_run(num_runs, num_cores_min, num_cores_max, rx_rate_matrix, write_mode, version_name, output_folder):
    header = []
    for i in range(num_cores_min, num_cores_max + 1):
        for j in range(0, num_runs):
            header.append(f"{i} core(s), run {j}")
    data = []
    for x in rx_rate_matrix:
        data.extend(x)
    output_file = f"{output_folder}/{RX_RATE_FILE_NAME_EACH_RUN}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(data)
    f.close()

def write_avg_rx_rate(num_cores_min, num_cores_max, rx_rate_matrix, write_mode, version_name, output_folder):
    avg_rx_rate_list = []
    for x in rx_rate_matrix:
        avg = sum(x) / len(x)
        # print(f"avg = {avg}")
        avg_rx_rate_list.append(avg)
    output_file = f"{output_folder}/{RX_RATE_FILE_NAME}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    header = list(range(num_cores_min, num_cores_max + 1))
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(avg_rx_rate_list)
    f.close()

    stdev_list = []
    for x in rx_rate_matrix:
        sd = 0
        if len(x) > 1:
            sd = stdev(x)
        # print(f"stdev = {sd}")
        stdev_list.append(sd)
    output_file = f"{output_folder}/{RX_RATE_FILE_NAME_STDEV}"
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

def plot_progs_avg_rx_rate(num_cores_min, num_cores_max, input_folder, prog_name, version_name_list, version_name_show_list,
    output_folder, trex_stats_version):
    # read Standard Deviation from csv file
    input_file = f"{input_folder}/{RX_RATE_FILE_NAME_STDEV}"
    stdev_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of stdev in {input_file}. Stop plotting")
        return
    # read average rx_rate from csv file
    input_file = f"{input_folder}/{RX_RATE_FILE_NAME}"
    avg_rx_rate_list = read_data_from_csv_file(input_file)
    if len(stdev_list) != len(version_name_list):
        print(f"ERROR: # of version_name_list != # of avg_rx_rate_list in {input_file}. Stop plotting")
        return

    # plot the figure with error bar
    font = {'weight' : 'bold',
            'size'   : 14}
    matplotlib.rc('font', **font)
    plt.figure()
    plt.title(f"{prog_name}  {trex_stats_version}", fontweight='bold')
    plt.xlabel("Number of cores", fontweight='bold')
    plt.ylabel("Average rx rate (Gbps)", fontweight='bold')
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    # plot a curve for each version
    for i, version_name in enumerate(version_name_list):
        print(f"version name: {version_name}")
        plt.plot(x, avg_rx_rate_list[i], label=version_name_show_list[i], linewidth=5)
        plt.errorbar(x, avg_rx_rate_list[i], yerr=stdev_list[i], fmt='o', capsize=6)
    plt.legend()
    # plt.legend(loc='lower right')
    output_file = f"{output_folder}/{RX_RATE_FILE_NAME_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file)

def visualize_prog_avg_rx_rate_bps(prog_name, version_name_list, version_name_show_list,
    num_runs, num_cores_min, num_cores_max, input_folder, trex_stats_versions, output_folder,
    extra_header_size_list, md_elem_size_list):
    global EXTRA_HEADER_SIZE, MD_ELEM_SIZE;
    for trex_stats_v in trex_stats_versions:
        output_folder_v = f"{output_folder}/{trex_stats_v}"
        if not exists(output_folder_v):
            os.system(f"sudo mkdir -p {output_folder_v}")
        first_flag = True
        for index, version_name in enumerate(version_name_list):
            rx_rate_matrix = []
            assert(len(extra_header_size_list) > index)
            assert(len(md_elem_size_list) > index)
            EXTRA_HEADER_SIZE = extra_header_size_list[index]
            MD_ELEM_SIZE = md_elem_size_list[index]
            for i in range(num_cores_min, num_cores_max + 1):
                rx_rate_list = rx_rate_multiple_run(num_runs, f"{input_folder}/{version_name}/{i}", trex_stats_v, i)
                rx_rate_matrix.append(rx_rate_list)
            if first_flag is True:
                write_mode = "w"
                first_flag = False
            else:
                write_mode = "a+"
            write_rx_rate_each_run(num_runs, num_cores_min, num_cores_max, rx_rate_matrix, write_mode, version_name, output_folder_v)
            write_avg_rx_rate(num_cores_min, num_cores_max, rx_rate_matrix, write_mode, version_name, output_folder_v)

        plot_progs_avg_rx_rate(num_cores_min, num_cores_max, output_folder_v, prog_name, version_name_list, version_name_show_list,
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
    extra_header_size = 0
    md_elem_size = 0
    visualize_prog_avg_rx_rate_bps(prog_name, version_name_list, version_name_show_list,
        num_runs, num_cores_min, num_cores_max, input_folder, trex_stats_versions, output_folder,
        extra_header_size, md_elem_size)
