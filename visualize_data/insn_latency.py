from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np

INSN_FILE_NAME = "perf.txt" # input file. instruction level raw data from perf
PROG_LATENCY_FILE_NAME_EACH_RUN = "latency.csv"
LATENCY_FILE_NAME = "avg_insn_latency.csv"
LATENCY_FILE_NAME_STDEV = "avg_insn_latency_stdev.csv"
LATENCY_FILE_NAME_EACH_RUN = "insn_latency.csv"
LATENCY_FILE_NAME_FIG = "avg_insn_latency.pdf"

# return the percent of all selected instructions
def percent_single_run(input_file, insn_ids):
    if len(insn_ids) == 0:
        print(f"ERROR: no instruction selected. Return percent = 0")
        return 0
    insns_percent = 0.0 # the type of percent is float
    insn_ids.sort()
    print("insn_ids: ", insn_ids)
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return percent = 0")
        return 0
    i = 0 # starts from insn_ids[i]
    f = open(input_file, "r")
    for line in f:
        line = line.strip().replace(':', ' ').split()
        if len(line) < 3: # at least 3 items: percent, insn_id, insn opcode
            continue
        if line[1] == insn_ids[i]:
            print("line:", line)
            insns_percent += float(line[0])
            i += 1
            if i == len(insn_ids):
                break
    f.close()
    if i != len(insn_ids):
        print(f"ERROR: no able to find all selected instructions in {input_file}. Return percent = 0")
        return 0
    print("insns_percent:", insns_percent)
    return insns_percent

def percent_multiple_run(num_runs, input_folder, insn_ids):
    percent_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{INSN_FILE_NAME}"
        print(f"processing {input_file}")
        percent = percent_single_run(input_file, insn_ids)
        print(f"{i}: {percent}")
        percent_list.append(percent)

    return percent_list

# write the estimated insn latency to file
def write_insn_latency_each_run(num_runs, num_cores_min, num_cores_max, insn_latency_matrix, write_mode, version_name, output_folder):
    header = []
    for i in range(num_cores_min, num_cores_max + 1):
        for j in range(0, num_runs):
            header.append(f"{i} core(s), run {j}")
    data = []
    for x in insn_latency_matrix:
        data.extend(x)
    output_file = f"{output_folder}/{LATENCY_FILE_NAME_EACH_RUN}"
    print(f"output: {output_file}")
    f = open(output_file, write_mode)
    writer = csv.writer(f)
    if write_mode == "w":
        writer.writerow(header)
    writer.writerow(data)
    f.close()

def write_avg_insn_latency(num_cores_min, num_cores_max, insn_latency_matrix, write_mode, version_name, output_folder):
    avg_latency_list = []
    for x in insn_latency_matrix:
        avg = sum(x) / len(x)
        print(f"avg = {avg}")
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
    for x in insn_latency_matrix:
        sd = stdev(x)
        print(f"stdev = {sd}")
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

def plot_progs_avg_insn_latency(num_cores_min, num_cores_max, input_folder, prog_name, version_name_list, output_folder):
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
    plt.ylabel("Average latency (cycles)")
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    # plot a curve for each version
    for i, version_name in enumerate(version_name_list):
        plt.plot(x, avg_latency_list[i], label=version_name)
        plt.errorbar(x, avg_latency_list[i], yerr=stdev_list[i], fmt='o', capsize=6)
    plt.legend(loc='lower right')
    output_file = f"{output_folder}/{LATENCY_FILE_NAME_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file)

# estimated insn latency = percent * program latency
def insn_latency_each_run(num_runs, num_cores_min, num_cores_max, percent_matrix, input_folder, version_id):
    insn_latency_matrix = []
    input_file = f"{input_folder}/{PROG_LATENCY_FILE_NAME_EACH_RUN}"
    # read program latency from input_file
    latency_matrix = read_data_from_csv_file(input_file)
    cur_id = 0
    latency_list = latency_matrix[version_id]
    for percent_list in percent_matrix: # different number of cores
        insn_latency_list = []
        for percent in percent_list: # different runs
            insn_latency = percent * latency_list[cur_id] / 100
            insn_latency_list.append(insn_latency)
            cur_id += 1
        insn_latency_matrix.append(insn_latency_list)
    if (cur_id != len(latency_list)):
        print("ERROR: program latency_list size does not match percent size")
    return insn_latency_matrix


def visualize_insn_avg_latency(prog_name, version_name_list, insn_ids, num_runs, num_cores_min, num_cores_max, input_folder, output_folder):
    if not exists(output_folder):
        os.system(f"sudo mkdir -p {output_folder}")
    first_flag = True
    for version_id, version_name in enumerate(version_name_list):
        percent_matrix = [] # percent_matrix[# of cores][run_id]
        for i in range(num_cores_min, num_cores_max + 1):
            print(version_id, i-num_cores_min, insn_ids[version_id][i-num_cores_min])
            percent_list = percent_multiple_run(num_runs, f"{input_folder}/{version_name}/{i}", insn_ids[version_id][i-num_cores_min])
            percent_matrix.append(percent_list)
        if first_flag is True:
            write_mode = "w"
            first_flag = False
        else:
            write_mode = "a+"

        # calculate the estimated insn latency
        prog_latency_each_run_folder = output_folder
        insn_latency_matrix = insn_latency_each_run(num_runs, num_cores_min, num_cores_max, 
                                                    percent_matrix, prog_latency_each_run_folder, 
                                                    version_id)
        write_insn_latency_each_run(num_runs, num_cores_min, num_cores_max, insn_latency_matrix, 
                                    write_mode, version_name, output_folder)
        write_avg_insn_latency(num_cores_min, num_cores_max, insn_latency_matrix, write_mode, 
                               version_name, output_folder)

    plot_progs_avg_insn_latency(num_cores_min, num_cores_max, output_folder, prog_name, version_name_list, output_folder)

if __name__ == "__main__":
    input_folder = "/mydata/test3/xdpex1"
    output_folder = "/mydata/test3/xdpex1/analyze_v2"
    num_cores_min = 1
    num_cores_max = 8 # from 1 to 8
    num_runs = 5
    prog_name = "xdpex1"
    version_name_list = ["v2"]
    insn_ids_version = [["84", "88", "8b"],
                        ["92", "96", "99"],
                        ["99", "9d", "a0"],
                        ["a4", "a8", "ab"],
                        ["ab", "af", "b2"],
                        ["b2", "b6", "b9"],
                        ["bd", "c1", "c4"],
                        ["c4", "c8", "cb"]]
    # for i in range(num_cores_min, num_cores_max + 1):
    #     insn_ids_version.append(["0", "7f"])
    insn_ids = []
    for i in range(len(version_name_list)):
        insn_ids.append(insn_ids_version)
    print(insn_ids)
    visualize_insn_avg_latency(prog_name, version_name_list, insn_ids, num_runs, num_cores_min, num_cores_max, input_folder, output_folder)
