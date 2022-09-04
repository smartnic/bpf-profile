# sudo python3 run.py

import subprocess
import os
import time

def get_prog_tag():
    cmd = "bpftool prog show | grep bpf_prog"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
    except:
        print ("ERROR: no bpf_prog found! not able to get program tag")
        raise
        return
    tag = output.split()[5]
    print(tag)
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
    cmd = "nohup taskset -c " + str(core_id) + " " + cmd + " >/dev/null 2>&1 &"
    run_cmd(cmd, wait=False)

# test prog across cores
# para core_num: the number of cores
# para seconds: measurement duration
def run_test(prog_name, core_num, seconds, output_folder):
    print("Test",  prog_name, "across", str(core_num), "core(s) for", str(seconds), "seconds...")
    run_cmd("mkdir tmp", wait=True)
    # run the user space program on core 0 to create maps, load and attach bpf program
    cmd = "./sock_test " + prog_name
    run_cmd_on_core(cmd, 0)
    # run ping commands
    ping_cmd = "ping -4 -i 0.00001 localhost"
    for i in range(1, core_num + 1):
        run_cmd_on_core(ping_cmd, i)
    time.sleep(1)

    # measure program
    # use perf to do instruction level sampling
    tag = ""
    try:
        tag = get_prog_tag()
    except:
        pass # do nothing
    core_ids = "1-" + str(core_num)
    out_file = "tmp/" + prog_name + "_perf.data"
    cmd = "sudo ./perf record -F 25250 --cpu " + core_ids + " -o " + out_file + " sleep " + str(seconds)
    run_cmd(cmd, wait=True)

    # use bpftool to get overall latency
    cmd = "sudo sysctl -w kernel.bpf_stats_enabled=1"
    run_cmd(cmd, wait=True)
    cmd = "sudo bpftool prog profile tag " + tag + " duration " + str(seconds) + " cycles instructions llc_misses > tmp/" + prog_name + "_prog.txt"
    run_cmd(cmd, wait=True)
    cmd = "sudo sysctl -w kernel.bpf_stats_enabled=0"
    run_cmd(cmd, wait=True)

    # clean environment
    run_cmd("pkill ping", wait=True)
    run_cmd("pkill sock_test", wait=True)

    # analyze perf data
    cmd = "sudo ./perf annotate -l -P bpf_prog_" + tag + "_bpf_prog1" + " -i " + out_file + " > tmp/" + prog_name + "_perf.txt"
    run_cmd(cmd, wait=True)
    run_cmd("sudo rm -rf " + out_file, wait=True)
    run_cmd("sudo mv tmp/* " + output_folder, wait=True)
    run_cmd("sudo rm -rf tmp", wait=True)
    # run_cmd("sudo rm -rf nohup.out")
    time.sleep(1)

def run_tests_test1(prog_name, core_num_max, seconds, output_folder):
    for i in range(1, core_num_max + 1):
        output_folder_i = output_folder + "/" + str(i)
        run_cmd("mkdir -p " + output_folder_i, wait=True)
        run_test(prog_name, i, max(100, seconds/i), output_folder_i)

def run_tests(prog_name, core_num_max, seconds, output_folder):
    for i in range(1, core_num_max + 1):
        output_folder_i = output_folder + "/" + str(i)
        run_cmd("mkdir -p " + output_folder_i, wait=True)
        prog_name_i = prog_name + "_p" + str(i)
        run_test(prog_name_i, i, max(100, seconds/i), output_folder_i)

if __name__ == "__main__":
    output_folder = "/proj/heartbeat-PG0/qwxu/bpf-profile/data5_100s/"
    core_num_max = 8
    duration = 100
    run_tests_test1("sock_test1_p1", core_num_max, duration, output_folder + "test1")
    run_tests("sock_test4", core_num_max, duration, output_folder + "test4")
    run_tests("sock_test5", core_num_max, duration, output_folder + "test5")
