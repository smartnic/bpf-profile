import socket
from socket_commands import *

IP = "172.16.90.134"  # The server's hostname or IP address
PORT = 65432  # The port used by the server

def send_command(cmd):
    print(f"send_command: {cmd}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((IP, PORT))
        s.sendall(bytes(cmd, 'utf-8'))
        data = s.recv(1024).decode('utf-8')
        if data == CMD_RECVD:
            return True
        else:
            return False

if __name__ == "__main__":
    res = send_command(CMD_START_TREX)
    print(f"res: {res}")
    res = send_command(CMD_STOP_SERVER)
    print(f"res: {res}")
