import argparse
from os.path import exists
from prog_latency import visualize_prog_avg_latency
from insn_latency import visualize_insn_avg_latency

def read_config_from_file(input_file, num_cores_min, num_cores_max):
    version_name_list = []
    insn_ids = []
    version_name_keyword = "version_name"
    insn_ids_keyword = "insn_ids_core_"
    cur_num_cores = num_cores_min
    insn_ids_version = []
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Return version_name_list = [], insn_ids = []")
        return [], []
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(":", 1)
        if len(line) < 2:
            continue
        if line[0] == version_name_keyword:
            version_name_list.append(line[1].strip())
        elif line[0] == f"{insn_ids_keyword}{cur_num_cores}":
            id_list = line[1].split()
            insn_ids_version.append(id_list)
            cur_num_cores += 1
        if cur_num_cores > num_cores_max:
            insn_ids.append(insn_ids_version)
            cur_num_cores = num_cores_min
            insn_ids_version = []
    f.close()
    return version_name_list, insn_ids

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-i', dest="input_folder", type=str, help='Input path', required=True)
    parser.add_argument('-o', dest="output_folder", type=str, help='output path', required=True)
    parser.add_argument('-b', dest="prog_name", type=str, help='Benchmark', required=True)
    parser.add_argument('-r', dest="num_runs", type=int, help='Total number of Runs (greater than 1)', required=True)
    parser.add_argument('--nc_min', dest="num_cores_min", type=int, help='Minimum number of cores (greater than 1)', required=False)
    parser.add_argument('--nc_max', dest="num_cores_max", type=int, help='Maximum number of cores (greater than 1)', required=True)
    parser.add_argument('--config', dest="config_file", type=str, help='The path of config file which contains version names, insn ids', required=True)
    args = parser.parse_args()

    if args.num_cores_min is None:
        args.num_cores_min = 1

    print(args.input_folder, args.prog_name, args.num_runs, args.num_cores_max, args.num_cores_min)
    version_name_list, insn_ids = read_config_from_file(args.config_file, args.num_cores_min, args.num_cores_max)
    print("version name list: ", version_name_list)
    print("insn_ids: ", insn_ids)

    visualize_prog_avg_latency(args.prog_name, version_name_list, args.num_runs, args.num_cores_min,
                               args.num_cores_max, args.input_folder, args.output_folder)
    visualize_insn_avg_latency(args.prog_name, version_name_list, insn_ids, args.num_runs, args.num_cores_min,
                               args.num_cores_max, args.input_folder, args.output_folder)
