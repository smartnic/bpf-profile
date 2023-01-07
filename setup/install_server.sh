#!/bin/sh

# The machine will reboot at the end of install_step1 and install_step2

usage() {
    echo "Usage: sh install_server.sh [number]. Number: 1, 2, 3, or verify"
}

install_step1() {
    # upgrade os: prepare for upgrading os
    sudo apt update && sudo apt upgrade
    sudo apt dist-upgrade
    sudo apt autoremove
    sudo reboot
}

install_step2() {
    # upgrade os
    sudo apt install update-manager-core
    sudo do-release-upgrade -d # upgrade
    sudo apt --purge autoremove
    sudo apt autoclean
    lsb_release -a

    # upgrade kernel
    mkdir tmp; cd tmp
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v6.0/amd64/linux-headers-6.0.0-060000_6.0.0-060000.202210022231_all.deb
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v6.0/amd64/linux-headers-6.0.0-060000-generic_6.0.0-060000.202210022231_amd64.deb
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v6.0/amd64/linux-modules-6.0.0-060000-generic_6.0.0-060000.202210022231_amd64.deb
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v6.0/amd64/linux-image-unsigned-6.0.0-060000-generic_6.0.0-060000.202210022231_amd64.deb
    sudo dpkg -i *.deb
    sudo reboot
}

install_step3() {
    # upgrade kernel: remove the temporary folder used in upgrading kernel
    uname -r
    rm -rf tmp

    # install dependencies
    sudo apt-get install clang llvm 
    sudo apt-get install linux-tools-common linux-tools-generic libelf-dev libbfd-dev
    sudo apt-get install binutils-dev libdw-dev systemtap-sdt-dev libunwind-dev 
    sudo apt-get install libslang2-dev libgtk2.0-dev libperl-dev python2-dev libzstd-dev libcap-dev 
    sudo apt-get install libnuma-dev libbabeltrace-dev libbabeltrace-ctf-dev libaudit-dev libiberty-dev
    sudo apt-get install htop
    sudo apt-get install python3-matplotlib

    # download linux source code
    wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-6.0.tar.gz
    tar -xvf linux-6.0.tar.gz
    rm -rf linux-6.0.tar.gz

    # build perf
    cd linux-6.0/tools/perf/
    make
    cp perf ../../../

    # build bpftool
    cd ../bpf/bpftool/
    make
    make install
    sudo make install

    # compile bpf samples
    cd ../../../
    make -C tools clean
    make -C samples/bpf clean
    make clean
    make defconfig
    make prepare
    make headers_install
    make -j20 VMLINUX_BTF=/sys/kernel/btf/vmlinux -C samples/bpf

    # install pcm
    sudo apt-get install pcm
}

verify() {
    echo "......Check OS version......"
    lsb_release -a
    echo "\n......Check kernel version......"
    uname -r
    echo "\n......Check perf version......"
    ~/perf version
    echo "\n......Check bpftool version......"
    bpftool version
    echo "\n......Check pcm is installed......"
    sudo pcm version
}

if [ $# -ne 1 ]
    then usage
else
    if [ $1 = "verify" ]
        then verify
    elif [ $1 -eq 1 ]
        then install_step1
    elif [ $1 -eq 2 ]
        then install_step2
    elif [ $1 -eq 3 ]
        then install_step3
    else usage
    fi
fi
