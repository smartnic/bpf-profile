# nohup sudo sh -c 'python3 -u profile-xdp.py  1>log.txt 2>err.txt &'

import subprocess
import os
import time
from os.path import expanduser

home = expanduser("~")
START_PORT=12

def get_prog_tag():
    cmd = "bpftool prog show | grep xdp"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
    except:
        print ("ERROR: no xdp found! not able to get program tag")
        raise
        return
    tag = output.split()[5]
    print(f"program tag is {tag}")
    return tag

def run_cmd(cmd, wait=True):
    print(cmd)
    if wait is True:
        process = subprocess.Popen(cmd, shell=True, close_fds=True)
        process.wait()
    else:
        os.system(cmd)
        # subprocess.run(cmd.split(), shell=True)

# run a command
# para cmd: the command to run. type: string
def run_cmd_on_core(cmd, core_id):
    cmd = f"nohup sudo -b taskset -c {str(core_id)} {cmd} >/dev/null 2>&1 &"
    run_cmd(cmd, wait=False)

def clean_environment(client):
    run_cmd("sudo bpftool net detach xdp dev ens1f1np1")
    # stop packet generation
    client_cmd = f"pkill -f send_udp_packets_for_xl170.py >/dev/null 2>&1 &"
    cmd = f"ssh -p 22 {client} \"nohup sudo sh -c '{client_cmd}'\""
    run_cmd(cmd)
    client_cmd = f"pkill tcpreplay >/dev/null 2>&1 &"
    cmd = f"ssh -p 22 {client} \"nohup sudo sh -c '{client_cmd}'\""
    run_cmd(cmd)
    run_cmd("pkill -f xdpex1", wait=True)

def run_test(prog_name, core_list, client, seconds, output_folder):
    # 1. print test name
    print("Test",  prog_name, "across", len(core_list), "core(s) for", str(seconds), "seconds...")
    run_cmd("mkdir tmp", wait=True)
    # 2. start packet generation
    for i in core_list:
        client_cmd = f"sh -c 'python3 -u {home}/xdp-profile/send_udp_packets_for_xl170.py {str(START_PORT+i)} >/dev/null 2>&1 &'"
        cmd = f"ssh -p 22 {client} \"nohup sudo {client_cmd}\""
        run_cmd(cmd)
    # 3. load and attach xdp program
    run_cmd("sudo bpftool net detach xdp dev ens1f1np1")
    cmd = f"./xdpex1 -I {prog_name} -N ens1f1np1"
    run_cmd_on_core(cmd, 0)

    # wait some seconds for the packet generation start sending packets
    # wait until tcpreplay starts
    time.sleep(60)

    # 4. measure the xdp prorgam
    try:
        tag = get_prog_tag()
    except:
        print(f"ERROR: not able to get the tag of {prog_name}. Test stop...")
        clean_environment(client)
        return

    # 4.1 use perf to do instruction level sampling
    tmp_out_file = "tmp/" + prog_name + "_perf.data"
    core_list_str = ",".join([str(x) for x in core_list])
    cmd = "sudo ./perf record -F 25250 --cpu " + core_list_str + " -o " + tmp_out_file + " sleep " + str(seconds)
    run_cmd(cmd, wait=True)

    # 4.2 use bpftool to get overall latency
    cmd = "sudo bpftool prog profile tag " + tag + " duration " + str(seconds) + " cycles instructions llc_misses > tmp/" + prog_name + "_prog.txt"
    run_cmd(cmd, wait=True)

    # 5. clean environment
    clean_environment(client)

    # 6. analyze perf data
    cmd = "sudo ./perf annotate -l -P bpf_prog_" + tag + "_xdp_prog" + " -i " + tmp_out_file + " > tmp/" + prog_name + "_perf.txt"
    run_cmd(cmd, wait=True)
    run_cmd("sudo rm -rf " + tmp_out_file, wait=True)
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    run_cmd("sudo rm -rf tmp", wait=True)
    time.sleep(5)

def run_tests(prog_name, core_num_max, duration, output_folder, num_runs):
    core_list = []
    for i in range(1, core_num_max + 1):
        core_list.append(i)
        for j in range(0, num_runs):
            output_folder_ij = output_folder + "/" + str(i) + "/" + str(j)
            run_cmd("sudo mkdir -p " + output_folder_ij, wait=True)
            run_test(prog_name, core_list, "hp065.utah.cloudlab.us", duration, output_folder_ij)

if __name__ == "__main__":
    output_folder = "/mydata/test1"
    core_num_max = 8
    duration = 100
    run_tests("xdpex1", core_num_max, 100, output_folder, 3)
