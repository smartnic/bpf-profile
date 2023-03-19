#!/bin/sh

dir=experiment
home="/data/local/qx51"
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
