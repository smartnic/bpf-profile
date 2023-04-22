#!/bin/bash
# RSS based on src ip
DOC="Script to setup ethtool filter steering to RX-queues"

if [ -z "$1" ]; then
    echo $DOC
    echo "Usage: $0 [DEVICE]"
    exit 1
fi
IFACE=$1

SRC_MAC_PRE="10:10:10:10:10:"
SRC_MAC_POST_START=0
NUM_RINGS=$(ethtool -n $IFACE| egrep '[0-9]+ RX rings available' | cut -f 1 -d ' ')
NUM_CORES=$(grep 'cpu cores' /proc/cpuinfo | uniq | awk '{print $4}')
num=$(( NUM_RINGS < NUM_CORES ? NUM_RINGS : NUM_CORES ))

for ring in $(seq 0 $(($num - 1))); do
    mac_post_dec=$((SRC_MAC_POST_START + $ring))
    mac_post_hex="$(printf '%02x' $mac_post_dec)"
    ethtool -N $IFACE flow-type ether src $SRC_MAC_PRE$mac_post_hex action $ring
done

echo "Display rx network flow classification rules"
ethtool --show-nfc $IFACE
