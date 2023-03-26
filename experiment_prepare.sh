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
# copy profile script
cp $home/bpf-profile/profile/profile-xdp.py .
cp $home/bpf-profile/profile/client.py .
cp $home/bpf-profile/profile/socket_commands.py .
