These benchmarks need to be compiled in the linux BPF samples

Use the following commands to compile benchmarks:
```
cd ~
wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-5.16.tar.gz
tar -xvf linux-5.16.tar.gz
rm -rf linux-5.16.tar.gz
sudo sh bpf-profile/samples/compile.sh
```