These benchmarks need to be compiled in the linux BPF samples

Use the following commands to compile benchmarks:
```
cd ~
wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-5.16.tar.gz
tar -xvf linux-5.16.tar.gz
rm -rf linux-5.16.tar.gz
sudo sh bpf-profile/samples/compile.sh
```

xdp_ddos_mitigator (RSS version, i.e., v2): https://github.com/polycube-network/polycube/blob/master/src/services/pcn-ddosmitigator/src/Ddosmitigator_dp.c

xdp_nat_dp (i.e., v1): https://github.com/polycube-network/polycube/blob/90fb0de21f8ed422c41cea2de2ab2437ac2dce8a/src/services/pcn-nat/src/Nat_dp.c

All scr versions use cuckoo map.

hhd:
- v1: shared state (atomic)
- v2: sharding
- v4: sharding (cuckoo map)
- v10: scr
- v11: scr (only tcp packets)
- v12: rss++

ddos_mitigator
- v1: shared state (atomic)
- v2: sharding
- v4: scr
- v5: sharding (cuckoo map)
- v6: scr (only tcp packets)
- v7: rss++

token_bucket
- v1: shared state (spinlock)
- v4: scr
- v5: sharding
- v6: sharding (cuckoo map)
- v7: scr (only tcp packets)
- v8: rss++

portknock
- v1: shared state (spinlock)
- v2: scr (only tcp packets)
- v4: sharding (cuckoo map)
- v5: rss++

Run RSS++
1. Upgrade kernel to `6.5.0-rsspp` ([kernel code](https://github.com/sebymiano/linux/tree/61c1e629df31cd19a0e208d6ebd978a4e51cd52b))

2. Boot from `6.5.0-rsspp`: we need to change default kernel in GRUB
   - Identify the target kernel entris (`rsspp/list-grub-menuentries.sh`): the following is `1>2`
   ```
   ....
   1>2 Ubuntu, with Linux 6.5.0-rsspp
   ...
   ```
   - Modify GRUB configuration in `/etc/default/grub`
     ```
     GRUB_DEFAULT='1>2'
     ```
   - Update GRUB `sudo update-grub` and reboot, and use `uname -r` to verify the kernel
