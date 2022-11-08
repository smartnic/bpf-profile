#!/bin/sh

dir=experiment
rm -rf $dir
mkdir $dir
cd $dir
# copy BPF benchmarks
cp ~/bpf-profile/samples/build/* .
# copy profile tools
cp ~/perf .
# copy machine config
cp ~/bpf-profile/profile/config.xl170 .
# copy profile script
cp ~/bpf-profile/profile/profile-xdp.py .
