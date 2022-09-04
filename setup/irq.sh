#!/bin/bash
# Taken from xdp_paper repository
function root_check_run_with_sudo() {
    # Trick so, program can be run as normal user, will just use "sudo"
    #  call as root_check_run_as_sudo "$@"
    if [ "$EUID" -ne 0 ]; then
        if [ -x $0 ]; then # Directly executable use sudo
            echo "Not root, running with sudo"
            sudo "$0" "$@"
            exit $?
        fi
        err 4 "cannot perform sudo run of $0"
    fi
}
root_check_run_with_sudo "$@"

# Disable Ethernet flow-control, this is network overload test
echo " --- Disable Ethernet flow-control ---"
ethtool -A $1 rx off tx off

# For optimal performance align NIC HW queue IRQs
# and make sure irqbalance don't reorder these
pkill irqbalance

echo " --- Align IRQs : mlx5 ---"
echo "Note: This is supposed to error if it is an Intel NIC"
for F in /proc/irq/*/mlx5_comp*/../smp_affinity; do
	dir=$(dirname $F) ;
	cat $dir/affinity_hint > $F
done
grep -H . /proc/irq/*/mlx5_comp*/../smp_affinity_list
