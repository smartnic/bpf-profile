#!/bin/bash
NUM_CORES=14
BPF_PROGS="xdp_token_bucket_v1 xdp_token_bucket_v6 xdp_token_bucket_v7 xdp_token_bucket_v8 \
	xdp_ddos_mitigator_v1 xdp_ddos_mitigator_v5 xdp_ddos_mitigator_v6 xdp_ddos_mitigator_v7 \
	xdp_hhd_v1 xdp_hhd_v4 xdp_hhd_v11 xdp_hhd_v12 \
	xdp_portknock_v1 xdp_portknock_v2 xdp_portknock_v4 xdp_portknock_v6"
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
rm -f *.o_[1-14]
