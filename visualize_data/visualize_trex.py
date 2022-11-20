import argparse
from os.path import exists
from rx_rate import visualize_prog_avg_rx_rate
from avg_roundtrip_latency import visualize_prog_avg_roundtrip_latency
from drop_rate import visualize_prog_avg_drop_rate

def read_config_from_file(input_file, num_cores_min, num_cores_max):
    version_name_list = []
    version_name_show_list = []
    insn_ids = []
    version_name_keyword = "version_name"
    version_name_show_keyword = "version_name_show"
    insn_ids_keyword = "insn_ids_core_"
    cur_num_cores = num_cores_min
    insn_ids_version = []
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. \
            Return version_name_list = [], version_name_show_list = [], insn_ids = []")
        return [], [], []
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(":", 1)
        if len(line) < 2:
            continue
        if line[0] == version_name_keyword:
            version_name_list.append(line[1].strip())
        elif line[0] == version_name_show_keyword:
            version_name_show_list.append(line[1].strip())
        elif line[0] == f"{insn_ids_keyword}{cur_num_cores}":
            id_list = line[1].split()
            insn_ids_version.append(id_list)
            cur_num_cores += 1
        if cur_num_cores > num_cores_max:
            insn_ids.append(insn_ids_version)
            cur_num_cores = num_cores_min
            insn_ids_version = []
    f.close()
    return version_name_list, version_name_show_list, insn_ids

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-i', dest="input_folder", type=str, help='Input path', required=True)
    parser.add_argument('-o', dest="output_folder", type=str, help='output path', required=True)
    parser.add_argument('-b', dest="prog_name", type=str, help='Benchmark', required=True)
    parser.add_argument('-r', dest="num_runs", type=int, help='Total number of Runs (greater than 1)', required=True)
    parser.add_argument('--nc_min', dest="num_cores_min", type=int, help='Minimum number of cores (greater than 1)', required=False)
    parser.add_argument('--nc_max', dest="num_cores_max", type=int, help='Maximum number of cores (greater than 1)', required=True)
    parser.add_argument('--config', dest="config_file", type=str, help='The path of config file which contains version names, insn ids', required=True)
    parser.add_argument('--tx_rate_list', dest="tx_rate_list", default=[1], help='TX rate (Mpps) list when pktgen is trex, e.g., 1,3. The default list is [1].', required=False)
    parser.add_argument('--trex', action='store_true', help='Visualize trex data', required=False)
    parser.add_argument('--prog_latency', action='store_true', help='Visualize prog latency data', required=False)
    parser.add_argument('--prog_latency_ns', action='store_true', help='Visualize prog latency (ns) data', required=False)
    parser.add_argument('--insn_latency', action='store_true', help='Visualize insn latency data', required=False)
    parser.add_argument('--pcm', action='store_true', help='Visualize pcm data', required=False)
    args = parser.parse_args()

    if args.num_cores_min is None:
        args.num_cores_min = 1

    print(args.input_folder, args.prog_name, args.num_runs, args.num_cores_max, args.num_cores_min)
    version_name_list, version_name_show_list, _ = read_config_from_file(args.config_file, args.num_cores_min, args.num_cores_max)
    print("version name list: ", version_name_list)
    print("version name show list: ", version_name_show_list)

    tx_rate_list = args.tx_rate_list.split(',')
    for tx in tx_rate_list:
        input_folder = f"{args.input_folder}/{tx}"
        output_folder = f"{args.output_folder}/{tx}"
        trex_stats_versions = []
        if args.trex:
            trex_stats_versions.append("no_profile")
        if args.prog_latency:
            trex_stats_versions.append("prog")
        if args.prog_latency_ns:
            trex_stats_versions.append("prog_ns")
        if args.insn_latency:
            trex_stats_versions.append("perf")
        if args.pcm:
            trex_stats_versions.append("pcm")
        visualize_prog_avg_rx_rate(args.prog_name, version_name_list, version_name_show_list,
            args.num_runs, args.num_cores_min, args.num_cores_max, input_folder, trex_stats_versions, output_folder)
        visualize_prog_avg_roundtrip_latency(args.prog_name, version_name_list, version_name_show_list,
            args.num_runs, args.num_cores_min, args.num_cores_max, input_folder, trex_stats_versions, output_folder)
        visualize_prog_avg_drop_rate(args.prog_name, version_name_list, version_name_show_list,
            args.num_runs, args.num_cores_min, args.num_cores_max, input_folder, trex_stats_versions, output_folder)
