## 0. Get machines on Cloudlab

Select profile `trex-xl170`.

## 1. Server (DUT) node-0

#### a. Upgrade OS and Kernel

Caveat: the machine will reboot after running `sudo sh install_server.sh 1` or `sudo sh install_server.sh 2`.
```
cd ~
git clone https://github.com/smartnic/bpf-profile.git
cp bpf-profile/setup/install_server.sh .
sudo sh install_server.sh 1
sudo sh install_server.sh 2
```
Check whether the Kernel version is `5.16.0-051600rc5-generic` using `uname -r`. If not, rerun the following command.
```
sudo sh install_server.sh 2
```

#### b. Install profiling tools and compile kernel BPF samples
```
sudo sh install_server.sh 3
```

#### c. Check whether the installation is successful

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

#### d. Setup RSS, IRQ, CPU frequency
Replace `ens1f1np1` with the interface on your machine.
```
cd ~/bpf-profile/setup
sudo bash setup_server.sh ens1f1np1
```

#### 5. Update machine config file 

Update machine config file `bpf-profile/profile/config.xl170` on node-0 with the information on your experiment machines. You could use `ifconfig` to figure out the MAC and IP addresses.

## 2. Client (Packet generator) node-1

#### a. clone repository and update machine config file
```
cd ~; git clone https://github.com/smartnic/bpf-profile.git
```

Modify machine config `bpf-profile/profile/config.xl170` file on node-1 with the information on your experiment machines. (The config file would be the same as the file on node-0).


#### b. Install TRex
Get the home directory
```
cd ~; pwd
```

Install MLNX_OFED
```
cd ~; sudo sh ~/bpf-profile/trex/install_mlnxofed.sh [home]
sudo reboot
```

Install and set up TRex
```
cd ~; sudo sh ~/bpf-profile/trex/install_setup_trex.sh [home]
```

#### c. (Optional) Check whether TRex is installed
Start TRex server
```
cd MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64/v2.87/; sudo ./t-rex-64 -i -c 10
```
Wait about 10 seconds until TRex server starts, then open a new terminal to send packets.
```
cd MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64/v2.87/
sudo python3 run_trex.py -b portknock -v v1 -t 3600 -r 1 -nc 1
```
TRex server will start sending packets with TX rate = 1Mpps. You could take a look at `Total-PPS` in the TRex server.

Finally, stop sending packets and TRex server. (`Warning`: you should stop them before running experiments.)

## 3. Run experiments
#### a. Set up ssh from the server (node-0) to the client (node-1)
On node-0, run the command to generate ssh key and get the public key.
```
sudo su
ssh-keygen
cat /root/.ssh/id_rsa.pub
```
Add the printed public key in the file `/root/.ssh/authorized_keys` on node-1.
Run the commands on node-0 to ssh into and exit node-1, and exit root user on node-0.
```
ssh -p 22 root@[node-1]
exit
exit
```
The following is an example for the ssh command.
```
ssh -p 22 root@hp047.utah.cloudlab.us
```

#### b. Compile BPF benchmarks on node-0
```
cd ~; sudo sh ~/bpf-profile/samples/compile.sh
```

#### c. Preparations for experiments on node-0
```
cd ~; sh ~/bpf-profile/experiment_prepare.sh
```

#### d. Run experiments on node-0
```
cd ~/experiment
nohup sudo sh -c 'python3 -u profile-xdp.py -o /mydata/xdp_portknock/ -b xdp_portknock -v v1,v2 -l xdpex1 -r 1 --nc_max 2 -d 30 --pktgen trex --tx_rate_list 1,11.5 1>log.txt 2>err.txt &'
```
You could run `python3 profile-xdp.py -h` for the argument description.
