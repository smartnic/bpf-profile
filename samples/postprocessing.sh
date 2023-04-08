#!/bin/bash
NUM_CORES=14
BPF_PROGS="xdp_token_bucket_v1 xdp_token_bucket_v4 \
	xdp_ddos_mitigator_v1 xdp_ddos_mitigator_v2 xdp_ddos_mitigator_v3 xdp_ddos_mitigator_v4 \
	xdp_hhd_v1 xdp_hhd_v5 xdp_hhd_v8 xdp_hhd_v9 xdp_hhd_v10 \
	xdp_portknock_v1 xdp_portknock_v2 xdp_portknock_v3 \
	xdp_nat_dp_v1 xdp_nat_dp_v3 \
	xdp_dummy_v1 \
	xdp_cuckoo_hash_v1"
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
