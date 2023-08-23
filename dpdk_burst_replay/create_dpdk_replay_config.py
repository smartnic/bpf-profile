import argparse
CONFIG_FILE = "config.yaml"

def traces_str(num_cores, pcap, tx_queues):
    item = f"  - path: \"{pcap}\"" + "\n" + f"    tx_queues: {tx_queues}\n"
    ret_str = "traces:\n"
    ret_str += item * num_cores
    return ret_str

def stats_str(pcie):
    ret_str = "stats:\n"
    ret_str += f"  - pci_id: {pcie}\n" + "    file_name: \"result_v1_core1.csv\"\n"
    return ret_str

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-o', dest="output_path", type=str, help='Output path of config file', required=True)
    parser.add_argument('--pcap', dest="pcap", type=str, help='pcap file path', required=True)
    parser.add_argument('-n', dest="num_cores", type=int, help='Number of cores used for packet generator (greater than 1)', required=True)
    parser.add_argument('--pcie', dest="pcie_addr", type=str, help='NIC PCIe address', required=True)
    parser.add_argument('--tx_queues', dest="tx_queues", type=int, help='Number of TX queues', required=True)
    parser.add_argument('--numacore', dest="numacore", type=int, help='NIC Numa id', required=True)
    args = parser.parse_args()
    config_str = "---\n"
    config_str += traces_str(args.num_cores, args.pcap, args.tx_queues)
    config_str += f"numacore: {args.numacore}\n"
    config_str += "nbruns: 100000000\n"
    config_str += "timeout: 6000\n"
    config_str += "max_bitrate: 10000000000\n"
    config_str += "write_csv: True\n"
    config_str += "wait_enter: False\n"
    config_str += "slow_mode: False\n"
    config_str += stats_str(args.pcie_addr)
    config_str += f"send_port_pci: {args.pcie_addr}\n"
    fout = open(f"{args.output_path}/{CONFIG_FILE}", "w")
    n = fout.write(config_str)
    fout.close()
