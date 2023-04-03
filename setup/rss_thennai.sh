#!/bin/bash
# RSS based on src ip
DOC="Script to setup ethtool filter steering to RX-queues"

if [ -z "$1" ]; then
    echo $DOC
    echo "Usage: $0 [DEVICE]"
    exit 1
fi
IFACE=$1

SRC_IP_PRE="10.10.1."
SRC_IP_POST_START=1
num=14
node1_ring_list=(1 2 3 4 5 6 7 17 18 19 20 21 22 23)
count=0

for i in $(seq 0 $(($num - 1))); do
	ring=${node1_ring_list[$i]}
    ip_post=$((SRC_IP_POST_START + $i))
    ethtool -N $IFACE flow-type ip4 src-ip $SRC_IP_PRE$ip_post action $ring
done

echo "Display rx network flow classification rules"
ethtool --show-nfc $IFACE
