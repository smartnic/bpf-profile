import socket
from socket_commands import *
import subprocess
import os
from os.path import exists
from mlffr import measure_mlffr

CONFIG_file_xl170 = "config.xl170"
IP = ""  # interface address
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

def read_machine_info_from_file(keyword):
    input_file = CONFIG_file_xl170
    res = None
    if not exists(input_file):
        print(f"ERROR: no such file {input_file}. Stop process...")
        sys.exit(0)
    f = open(input_file, "r")
    for line in f:
        line = line.strip().split(":", 1)
        if len(line) < 2:
            continue
        if line[0] == keyword:
            res = line[1].strip()
    f.close()
    if res is None:
        print(f"ERROR: no {keyword} in {input_file}. Stop process...")
        sys.exit(0)
    return res

def run_cmd(cmd, wait=True):
    print(cmd)
    if wait is True:
        process = subprocess.Popen(cmd, shell=True, close_fds=True)
        process.wait()
    else:
        os.system(cmd)
        # subprocess.run(cmd.split(), shell=True)

def measure_benchmark_mlffr(paras_str):
    paras = paras_str.split()
    if len(paras) < 8:
        return False, 0
    benchmark = paras[0]
    version = paras[1]
    num_cores = int(paras[2])
    num_flows = int(paras[3])
    measure_time = int(paras[4])
    rate_high = float(paras[5])
    rate_low = float(paras[6])
    precision = float(paras[7])
    mlffr = measure_mlffr(benchmark, version, num_cores, num_flows, 
                          measure_time, rate_high, rate_low, precision)
    return True, mlffr


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        IP = read_machine_info_from_file("client_tcp_ip")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((IP, PORT))
        while True:
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode('utf-8')
                if data:
                    print(f"Received: {data}")
                    if data == CMD_STOP_SERVER:
                        conn.sendall(bytes(CMD_RECVD, 'utf-8'))
                        print("stop server....")
                        s.shutdown(socket.SHUT_RDWR)
                        s.close()
                        break;
                    elif CMD_MEASURE_MLFFR in data:
                        paras = data.replace(CMD_MEASURE_MLFFR, "")
                        res, mlffr = measure_benchmark_mlffr(paras)
                        print(f"resp: {mlffr}")
                        conn.sendall(bytes(str(mlffr), 'utf-8'))
                    else:
                        conn.sendall(bytes(CMD_RECVD, 'utf-8'))
                        run_cmd(data)


if __name__ == "__main__":
    start_server()
