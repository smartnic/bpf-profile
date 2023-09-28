#!/bin/bash

home=""
config_file="bpf-profile/profile/config.xl170"
home_keyword="client_dir"
while read -r line
do
  if [[ "$line" == *"$home_keyword"* ]]; then
    IFS=" " read name home <<< "$line"
    break
  fi
done < "$config_file"
echo "client_dir is $home"

dir=$home/dpdk-burst-replay/src
cd $dir
cp $home/bpf-profile/profile/config.xl170 .
cp $home/bpf-profile/dpdk_burst_replay/create_dpdk_replay_config.py .
cp $home/bpf-profile/dpdk_burst_replay/measure.py .
cp $home/bpf-profile/dpdk_burst_replay/mlffr.py .
cp $home/bpf-profile/dpdk_burst_replay/server.py .
cp $home/bpf-profile/dpdk_burst_replay/socket_commands.py .
cp $home/bpf-profile/dpdk_burst_replay/eth_stat.sh .
