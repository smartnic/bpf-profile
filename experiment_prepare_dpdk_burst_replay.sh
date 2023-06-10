#!/bin/bash

home=""
config_file="bpf-profile/profile/config.xl170"
home_keyword="server_dir"
while read -r line
do
  if [[ "$line" == *"$home_keyword"* ]]; then
    IFS=" " read name home <<< "$line"
    break
  fi
done < "$config_file"
echo "server_dir is $home"

dir=experiment
rm -rf $dir
mkdir $dir
cd $dir
# copy BPF benchmarks
cp $home/bpf-profile/samples/build/* .
# copy profile tools
cp $home/perf .
# copy machine config
cp $home/bpf-profile/profile/config.xl170 .
cp $home/bpf-profile/dpdk_burst_replay/utils.py .
cp $home/bpf-profile/dpdk_burst_replay/client.py .
cp $home/bpf-profile/dpdk_burst_replay/socket_commands.py .
cp $home/bpf-profile/dpdk_burst_replay/profile_xdp_dpdk_burst_replay.py .
