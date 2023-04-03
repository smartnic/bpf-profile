#!/bin/bash
DOC="Script to delete ethtool filter steering to RX-queues"

if [[ -z "$1" || -z "$2" || -z "$3" ]]; then
    echo $DOC
    echo "Usage: bash $0 [DEVICE] [RULE# START] [RULE# END]"
    exit 1
fi
IFACE=$1
RULE_START=$2
RULE_END=$3
echo "Delete $RULE_START - $RULE_END on $IFACE"

for ring in $(seq $RULE_START $RULE_END); do
    ethtool -N $IFACE delete $ring
done

echo "Display rx network flow classification rules"
ethtool --show-nfc $IFACE
