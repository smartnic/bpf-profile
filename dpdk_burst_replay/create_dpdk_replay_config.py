import argparse
import os

def traces_str(num_cores, pcap, tx_queues):
    item = f"  - path: \"{pcap}\"" + "\n" + f"    tx_queues: {tx_queues}\n"
    ret_str = "traces:\n"
    ret_str += item * num_cores
    return ret_str

def stats_str(pcie):
    ret_str = "stats:\n"
    ret_str += f"  - pci_id: {pcie}\n" + "    file_name: \"result_v1_core1.csv\"\n"
    return ret_str

def create_dpdk_replay_config(num_cores, pcap, tx_queues, numacore, max_mpps, pcie_addr, output_path, fname):
    config_str = "---\n"
    config_str += traces_str(num_cores, pcap, tx_queues)
    config_str += f"numacore: {numacore}\n"
    config_str += "nbruns: 100000000\n"
    config_str += "timeout: 6000\n"
    config_str += f"max_mpps: {max_mpps:.2f}\n"
    config_str += "max_mbps: -1\n"
    config_str += "write_csv: True\n"
    config_str += "wait_enter: False\n"
    config_str += "slow_mode: False\n"
    config_str += stats_str(pcie_addr)
    config_str += f"send_port_pci: {pcie_addr}\n"
    config_str += "loglevel: INFO\n"
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    fout = open(f"{output_path}/{fname}", "w")
    fout.write(config_str)
    fout.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about data')
    parser.add_argument('-o', dest="output_path", type=str, help='Output path of config file', required=True)
    parser.add_argument('--fname', dest="fname", type=str, help='Output config file name', required=True)
    parser.add_argument('--max_mpps', dest="max_mpps", type=float, help='tx rate in mpps', default = -1, required=False)
    parser.add_argument('--pcap', dest="pcap", type=str, help='pcap file path', required=True)
    parser.add_argument('-n', dest="num_cores", type=int, help='Number of cores used for packet generator (greater than 1)', required=True)
    parser.add_argument('--pcie', dest="pcie_addr", type=str, help='NIC PCIe address', required=True)
    parser.add_argument('--tx_queues', dest="tx_queues", type=int, help='Number of TX queues', required=True)
    parser.add_argument('--numacore', dest="numacore", type=int, help='NIC Numa id', required=True)
    args = parser.parse_args()
    create_dpdk_replay_config(args.num_cores, args.pcap, args.tx_queues, args.numacore,
        args.max_mpps, args.pcie_addr, args.output_path, args.fname)
