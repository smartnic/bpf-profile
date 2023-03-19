import socket
from socket_commands import *
import subprocess
import os

IP = "172.16.90.134"  # interface address
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

def run_cmd(cmd, wait=True):
    print(cmd)
    if wait is True:
        process = subprocess.Popen(cmd, shell=True, close_fds=True)
        process.wait()
    else:
        os.system(cmd)
        # subprocess.run(cmd.split(), shell=True)

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
                    else:
                        conn.sendall(bytes(CMD_RECVD, 'utf-8'))
                        run_cmd(data)


if __name__ == "__main__":
    start_server()
