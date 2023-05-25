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
core_list=(9 10 11 12 13 14 15 1 2 3 4 5 6 7)
# irq numbers may be different on different machines
irq_list_pungai=(225 226 227 228 229 230 231 232 233 234 235 236 237 238)
irq_list=("${irq_list_pungai[@]}")
num=14
for i in $(seq 0 $(($num - 1))); do
    core=$((1 << ${core_list[$i]}))
    core_hex="$(printf '%08x' $core)"
    irq_num=${irq_list[$i]}
    echo $core_hex > /proc/irq/$irq_num/mlx5_comp*/../smp_affinity
done
grep -H . /proc/irq/*/mlx5_comp*/../smp_affinity_list
