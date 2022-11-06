#!/bin/sh

wget --no-check-certificate --no-cache https://trex-tgn.cisco.com/trex/release/v2.87.tar.gz
tar -xzvf v2.87.tar.gz
sudo pip3 install trex-stl-lib
sudo pip3 install numpy
sudo cp ~/bpf-profile/trex/trex_cfg.yaml /etc/trex_cfg.yaml
sudo mkdir -p /root/bpf-profile/profile/
sudo cp ~/bpf-profile/profile/config.xl170 /root/bpf-profile/profile/
cd MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64/v2.87
cp ~/bpf-profile/trex/start_trex_server.sh .
cp ~/bpf-profile/trex/run_trex.sh .
cp ~/bpf-profile/trex/run_trex.py .
cp ~/bpf-profile/trex/trex_measure_start.py .
cp ~/bpf-profile/trex/trex_measure_stop.py .
cp ~/bpf-profile/trex/udp_for_benchmarks.py stl/
cp ~/bpf-profile/profile/send_udp_packets_portknock.py stl/
cp ~/bpf-profile/profile/send_udp_packets_hhd.py stl/
