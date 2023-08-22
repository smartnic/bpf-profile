#!/bin/bash

set_freq() {
	# make both min and max to the advertised freq
	if [ -d /sys/devices/system/cpu/cpu0/cpufreq/ ]; then
		for i in $(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq); do echo "${CPU_FREQ_KHZ}" | sudo tee $i > /dev/null 2>&1 ;done
		for i in $(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq); do echo "${CPU_FREQ_KHZ}" | sudo tee $i > /dev/null 2>&1 ;done
	fi
}

dump_sys_state() {
	if [ -d /sys/devices/system/cpu/cpu0/cpufreq/ ]; then
		for i in $(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq); do echo "$i: $(cat $i)";done
		for i in $(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq); do echo "$i: $(cat $i)";done
	fi

	for i in $(ls /sys/devices/system/cpu/cpu*/cpuidle/state*/disable); do echo "$i: $(cat $i)";done
	sudo rdmsr -a 0x1a0 -f 38:38
}

CPU_FREQ_KHZ=$1
echo $CPU_FREQ_KHZ
set_freq
dump_sys_state
