### Preparation
Apply for two xl170 cloudlab machines with UBUNTU 20.04 OS version. Two machines are used as a server and a client 
separately. The server is used for loading the BPF program to be profiled, while the client is used for sending 
packets to the server to tigger the BPF program to run. 

### Installation

#### Installation on server
Run the following commands to install the profiling tools and build BPF programs on the server.

Caveat: the machine will reboot after running `sudo sh install_server.sh 1` or `sudo sh install_server.sh 2`.
```
cd ~
sudo sh install_server.sh 1
sudo sh install_server.sh 2
sudo sh install_server.sh 3
```

Check whether the installation is successful

```
sh install_server.sh verify
```
Expected output
```
......Check OS version......
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.1 LTS
Release:	22.04
Codename:	jammy

......Check kernel version......
5.16.0-051600rc5-generic

......Check perf version......
perf version 5.16.0

......Check bpftool version......
bpftool v5.16.0
features: libbfd, skeletons
```

##### Installation on client
Run the following commands to install the packet generation tool.
```
cd ~; sudo sh install_client.sh
```

##### Set up configurations on server

````
sudo ./setup_server.sh
````

### An example of profiling a BPF program
In this example, we will (1) use `bpftool` to measure the latency of an XDP program and (2) use `perf` to profile the XDP program at the instruction level.

Run the following command to load an XDP program on the server. `ens1f1np` is an interface on the server, which can be used to receive packets from the client. It might be different. You could use `ifconfig` to find the interface name on your machine. Please do not use the interface which is used for you using ssh to access the server. Otherwise, the connection will be broken.
```
cd ~/linux-5.16/samples/bpf
sudo ./xdp1 -N ens1f1np
```

Run the following command on the client to send packets from the client to the server. `send_udp_packets_for_xl170.py` is a script in `profile` folder in this repository. You might need to change the interface name, MAC addresses, and IP addresses.
```
sudo python3 send_udp_packets_for_xl170.py 13
```
It may take a while for the client to generate the packets. After seeing that the XDP program is triggered to run, we can 
start profiling the XDP program.
```
node0:~/linux-5.16/samples/bpf> sudo ./xdp1 -N ens1f1np1
start polling stats
proto 17:      85306 pkt/s
proto 17:     783290 pkt/s
proto 17:     782325 pkt/s
proto 17:     786737 pkt/s
proto 17:     786056 pkt/s
proto 17:     782645 pkt/s
```

Open a new terminal on the server, and run the following commands to use bpftool to measure the program latency.
The first command is used to get the tag of the XDP program. You might need to change `66bd567e1b61f277` to the tag
that you get in the first command.

```
node0:~> sudo bpftool prog show | grep xdp
3550: xdp  name xdp_prog1  tag 66bd567e1b61f277  gpl
	pids xdp1(107485)
node0:~> sudo bpftool prog profile tag 66bd567e1b61f277 duration 10 cycles

           7772977 run_cnt             
        4129942729 cycles
```
`4129942729/7772977` is the program latency.


Run the following commands to use perf to profile the program at the instruction level.
```
node0:~> sudo ~/perf record -a -F 25250 sleep 10
[ perf record: Woken up 0 times to write data ]
[ perf record: Captured and wrote 271.031 MB perf.data (5052743 samples) ]
node0:~> sudo ~/perf annotate -l -P bpf_prog_66bd567e1b61f277_xdp_prog1
```
