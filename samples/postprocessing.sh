#!/bin/bash
NUM_CORES=8
BPF_PROGS="xdp_hhd_v1 xdp_hhd_v2 xdp_hhd_v3 xdp_hhd_v4 xdp_hhd_v5 xdp_hhd_v6 xdp_hhd_v7"
rm -f *.o
for prog in $BPF_PROGS
do
	echo "processing ${prog}......"
	for i in $(seq 1 $NUM_CORES)
	do
		pattern=kern.o
		src_file=${prog}_${pattern}_${i}
		dst_file=${src_file//${pattern}_/p}_${pattern} # replace ${pattern}_ with 'p' in src_file
		cmd="mv $src_file $dst_file"
		echo $cmd
		$cmd
	done
done
rm -f *.o_[1-9]
