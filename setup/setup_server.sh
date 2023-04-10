#!/bin/bash
echo "Setting up configurations"
chmod +x constant_freq.sh
chmod +x irq.sh
chmod +x rss.sh
chmod +x toggle_hyperthreading.sh
sudo ethtool --set-priv-flags $1 rx_striding_rq off
sudo ethtool --set-priv-flags $1 rx_cqe_compress on
sudo ethtool --show-priv-flags $1
sudo ethtool -G $1 rx 256
echo "Running RSS"
sudo ./rss.sh $1
echo "Running IRQ"
sudo ./irq.sh $1
echo "Running constant_freq"
sudo ./constant_freq.sh
echo "Toggling hyperthreading"
sudo ./toggle_hyperthreading.sh
cd ../
echo "DONE"
