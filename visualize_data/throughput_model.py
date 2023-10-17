from os.path import exists
import os
import csv
from statistics import stdev
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
from matplotlib.ticker import FormatStrFormatter

# x-axis: # of cores; y-axis: mlffr
PROG_FILE_NAME = "mlffr.txt"
LATENCY_PROG_FILE_NAME = "prog_ns.txt"
MODEL_FILE_NAME_FIG = "throughput_model.pdf"
MODEL_COEFFICIENT_FILE = "coefficient.txt"

# data in the input file: count,rx_pps,tx_pps,diff,max_l,min_l,avg_l
# rx/tx rate in the input file is pps
def mlffr_single_run(input_file):
    mlffr = 0
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return mlffr = 0")
        return 0
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(',')
        # print(f"{len(line)}, line: {line}")
        if len(line) < 1:
            continue
        mlffr = float(line[0])
        # print(f"mlffr: {mlffr}")
        if mlffr != 0:
            break
    f.close()
    if mlffr == 0:
        print(f"ERROR: no mlffr in {input_file}. Return mlffr = 0")
        return 0
    return mlffr


def mlffr_multiple_run(num_runs, input_folder):
    mlffr_list = []
    for i in range(num_runs):
        input_file = f"{input_folder}/{i}/{PROG_FILE_NAME}"
        print(f"processing {input_file}")
        mlffr = mlffr_single_run(input_file)
        # print(f"{i}: {mlffr}")
        mlffr_list.append(mlffr)
    return mlffr_list


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
        input_file = f"{input_folder}/{i}/{LATENCY_PROG_FILE_NAME}"
        print(f"processing {input_file}")
        latency = latency_single_run(input_file)
        # print(f"{i}: {latency}")
        latency_list.append(latency)
    return latency_list


def get_predicted_list(version_name, cores_list, tx, latency_num_runs,
    mlffr_dic, num_cores_min, num_cores_max, input_folder, output_folder):
    # calculate c2
    latency_list = []
    for num_cores in cores_list:
        latency_list_fixed_cores = latency_multiple_run(latency_num_runs, f"{input_folder}/{tx}/{version_name}/{num_cores}")
        latency = sum(latency_list_fixed_cores) / len(latency_list_fixed_cores)
        latency_list.append(latency)
    x = np.array(cores_list)
    y = np.array(latency_list)
    adjusted_x = x - 1
    c2, c1 = np.polyfit(adjusted_x, y, 1)
    print(c1, c2)
    # Calculate the predicted y values
    predicted_y = c2 * (x - 1) + c1
    # Calculate the mean squared error
    mse = ((y - predicted_y) ** 2).mean()
    print(f"mse: {mse}")
    # calculate t (i.e., d + c1)
    t_list = []
    c = num_cores_max + 1
    for num_cores, mlffr in mlffr_dic.items():
        t = 1000 * num_cores/mlffr - c2 * (num_cores - 1)
        t_list.append(t)
        c = c - 1
        if c == 0:
            break
    print(t_list)
    t = sum(t_list) / len(t_list)
    print(t)
    # use d and t to predict throughput
    # pred_mlffr = n / (t + (n-1) * c2)
    pred_mlffr_list = []
    for n in range(num_cores_min, num_cores_max + 1):
        pred_mlffr = 1000 * n / (t + (n-1) * c2)
        pred_mlffr_list.append(pred_mlffr)
    print(pred_mlffr_list)
    output_file = f"{output_folder}/{MODEL_COEFFICIENT_FILE}"
    print(f"output: {output_file}")
    f = open(output_file, "w")
    writer = csv.writer(f)
    header = ["t", "c2", "d", "c1"]
    writer.writerow(header)
    d = t - c1
    writer.writerow([t, c2, d, c1])
    f.close()
    return pred_mlffr_list


def plot_progs_throughput_model(pred_mlffr_list, mlffr_matrix, num_cores_min,
    num_cores_max, num_runs, prog_name, output_folder):
    mlffr_list = []
    for run_id in range(0, num_runs):
        mlffr_list_single_run = []
        for x in mlffr_matrix:
            mlffr_list_single_run.append(x[run_id])
        mlffr_list.append(mlffr_list_single_run)
    # one_core_mlffr = mlffr_list[0]
    # mlffr_list = [a/one_core_mlffr for a in mlffr_list]
    print(mlffr_list)
    plt.figure()
    plt.rcParams['font.size'] = 20
    # Create a formatter to display y-axis labels with 1 digit
    # formatter = FormatStrFormatter('%.1f')
    formatter = FormatStrFormatter('%d')
    # Apply the formatter to the y-axis
    plt.gca().yaxis.set_major_formatter(formatter)
    plt.title(f"{prog_name}", fontweight='bold')
    plt.xlabel("Number of cores")
    plt.ylabel("Throughput")
    plt.grid()
    x = list(range(num_cores_min, num_cores_max + 1)) # different number of cores
    if len(x) == 7:
        plt.xticks(x, x)
    else:
        x_new = [2*a for a in range(1, 8)]
        plt.xticks(x_new, x_new)
    # plot a curve for each version
    # plt.plot(x, pred_mlffr_list, linestyle='-', marker='o', label='Predicted', markersize=12, linewidth=4)
    plt.plot(x, pred_mlffr_list, linestyle='-', label='Predicted', linewidth=4, zorder=4)
    flag = True
    for data in mlffr_list:
        if flag:
            label = 'Actual'
        else:
            label = None
        plt.scatter(x, data, marker='x', label=label, color = 'orange', s=100, zorder=5)
        flag = False
    # Create the legend with handles and labels in the order of appearance
    handles, labels = plt.gca().get_legend_handles_labels()
    plt.legend(handles, labels)
    # plt.legend(loc='lower right')
    output_file = f"{output_folder}/{MODEL_FILE_NAME_FIG}"
    print(f"output: {output_file}")
    plt.savefig(output_file, bbox_inches='tight')


def visualize_prog_throughput_model(prog_name, version_name, mlffr_num_runs, num_cores_min, num_cores_max,
    latency_cores_list, tx_rate, latency_num_runs, input_folder, output_folder):
    if not exists(output_folder):
        os.system(f"sudo mkdir -p {output_folder}")
    first_flag = True
    mlffr_matrix = []
    mlffr_dic = {}
    for i in range(num_cores_min, num_cores_max + 1):
        mlffr_list = mlffr_multiple_run(mlffr_num_runs, f"{input_folder}/{version_name}/{i}")
        mlffr_dic[i] = sum(mlffr_list) / len(mlffr_list)
        mlffr_matrix.append(mlffr_list)
    if first_flag is True:
        write_mode = "w"
        first_flag = False
    else:
        write_mode = "a+"
    print(f"mlffr_matrix: {mlffr_matrix}")
    predic_list = []
    pred_mlffr_list = get_predicted_list(version_name, latency_cores_list, tx_rate, latency_num_runs,
        mlffr_dic, num_cores_min, num_cores_max, input_folder, output_folder)
    plot_progs_throughput_model(pred_mlffr_list, mlffr_matrix, num_cores_min,
        num_cores_max, mlffr_num_runs, prog_name, output_folder)


if __name__ == "__main__":
    input_folder = "../../experiment_data/model/univ1_pt16_192"
    output_folder = "../../experiment_data/model/univ1_pt16_192/graph"
    num_cores_min = 1
    num_cores_max = 7
    mlffr_num_runs = 3
    prog_dic = {"xdp_token_bucket": "v7",
                "xdp_hhd": "v11",
                "xdp_ddos_mitigator": "v6",
                "xdp_portknock": "v2",
               }
    latency_cores_list = range(num_cores_min, num_cores_max + 1)
    tx_rate = 5
    latency_num_runs = 3
    for prog_name, version_name in prog_dic.items():
        input_folder_i = f"{input_folder}/{prog_name}"
        output_folder_i = f"{output_folder}/{prog_name}"
        visualize_prog_throughput_model(prog_name, version_name,
            mlffr_num_runs, num_cores_min, num_cores_max,
            latency_cores_list, tx_rate, latency_num_runs,
            input_folder_i, output_folder_i)
