#!/bin/sh

wget http://content.mellanox.com/ofed/MLNX_OFED-5.4-3.5.8.0/MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64.tgz
tar -xvzf MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64.tgz
sudo yum install pciutils createrepo
cd MLNX_OFED_LINUX-5.4-3.5.8.0-rhel7.9-x86_64
sudo ./mlnxofedinstall --with-mft --with-mstflint --dpdk --upstream-libs --add-kernel-support
sudo dracut -f
