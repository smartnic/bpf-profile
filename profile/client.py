import socket
from socket_commands import *
from os.path import exists

CONFIG_file_xl170 = "config.xl170"
IP = ""  # The server's hostname or IP address
PORT = 65432  # The port used by the server

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

def send_command(cmd):
    IP = read_machine_info_from_file("client_tcp_ip")
    print(f"send_command: {cmd}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((IP, PORT))
        s.sendall(bytes(cmd, 'utf-8'))
        data = s.recv(1024).decode('utf-8')
        return data

if __name__ == "__main__":
    res = send_command(CMD_START_TREX)
    print(f"res: {res}")
    res = send_command(CMD_STOP_SERVER)
    print(f"res: {res}")
