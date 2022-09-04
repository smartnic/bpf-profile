#!/bin/bash
echo "Setting up configurations"
chmod +x constant_freq.sh
chmod +x irq.sh
chmod +x rss.sh
sudo ethtool --set-priv-flags $1 rx_striding_rq off
sudo ethtool -G $1 rx 256
echo "Running RSS"
sudo ./rss.sh $1
echo "Running IRQ"
sudo ./irq.sh $1
cd ../
echo "DONE"
