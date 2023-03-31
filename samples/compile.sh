#!/bin/bash

home=""
config_file="bpf-profile/profile/config.xl170"
home_keyword="server_dir"
while read -r line
do
  echo "$line"
  if [[ "$line" == *"$home_keyword"* ]]; then
    echo "$line"
    IFS=" " read name home <<< "$line"
    break
  fi
done < "$config_file"
echo "server_dir is $home"
cp $home/bpf-profile/samples/*.c $home/linux-6.0/samples/bpf/
cp $home/bpf-profile/samples/*.h $home/linux-6.0/samples/bpf/
cp -r $home/bpf-profile/samples/lib $home/linux-6.0/samples/bpf/
cp $home/bpf-profile/samples/Makefile $home/linux-6.0/samples/bpf/
cp $home/bpf-profile/samples/postprocessing.sh $home/linux-6.0/samples/bpf/
cd $home/linux-6.0/
make -C tools clean
make -C samples/bpf clean
make clean
make defconfig
make prepare
make headers_install
make -j20 VMLINUX_BTF=/sys/kernel/btf/vmlinux -C samples/bpf
cd samples/bpf/
bash postprocessing.sh
rm -rf $home/bpf-profile/samples/build/ 
mkdir -p $home/bpf-profile/samples/build/ 
mv $home/linux-6.0/samples/bpf/*.o $home/bpf-profile/samples/build/
mv $home/linux-6.0/samples/bpf/xdpex1 $home/bpf-profile/samples/build/
mv $home/linux-6.0/samples/bpf/xdp_ddos_mitigator $home/bpf-profile/samples/build/
mv $home/linux-6.0/samples/bpf/xdp_nat_dp $home/bpf-profile/samples/build/
echo "output files are in bpf-profile/samples/build/"
