Applications: portknock (v6)

### Correctness tests
cases to evaluate (two cores)
- No packet lost: No lost packet is detected
  ```
  c1: scr pkt 1 (p1),   scr pkt 3 (p2-3), scr pkt 5 (p4-5), ...
  c2: scr pkt 2 (p1-2), scr pkt 4 (p3-4), scr pkt 6 (p5-6), ...
  ```
- SCR Packets lost at one round
    - SCR Packets lost at round 1
        - 1: recover p1 at core1
        - 2: recover p1-2 at core2
        - 1-2: detect p1 is lost at both cores, recover p2 at core1
    - SCR Packets lost at round 2
        - 3: recover p2-3 at core1
        - 4: recover p3-4 at core2
        - 3-4: recover p2 at core1, recover p4 at core2, p3 is lost at both cores
- SCR Packets lost at a few contiguous rounds
  - 1-3: p1-2 lost at both cores, recover p3 at core1
  - 2-4: p2-3 lost at both cores, recover p1,p4 at core2
  - 3-6: p3-5 lost at both cores, recover p2 at core1, recover p6 at core2 
- pkt_id overflow

### Configuration
- packet-processing core indexes: e.g., `int cores[] = {8, 9};`
- metadata log capacity: `METADATA_LOG_MAX_ENTIRES`. It should be 2^n
- waiting time: When a core detects packet loss, it needs to get metadata log from other cores. We need to ensure the core waits for enough time. Currently, we use `BPF_LOOP_MAX` iterations in bpf_loop(). We can call bpf_loop multiple times if one bpf_loop is not enough.
- Maximum number of contiguous lost packets that can be handled.
  - metadata log capacity (~1024). Limited by BPF (the size of a single map element)
  - maximum packet id (max uint32)

### Instructions for experiment
#### Pcap file examples
- lost-0.pcap: no packet lost
- lost-1.pcap: SCR packet 1 is lost
- lost-1_2.pcap: SCR packets 1-2 are lost

#### Instructions to run experiments
Receiver
terminal 1: `sudo ./xdpex1 -I xdp_portknock_v6_p2 -N ens114np0`
terminal 2: `sudo cat /sys/kernel/debug/tracing/trace_pipe > log-0.log`

Sender:
`sudo tcpreplay -i ens114np0 lost-0.pcap`

#### Read logs
Check metadata log update on core 8: `grep "\[008\].*add pkt.*ring" log-0.log`

Example output:
```
          <idle>-0       [008] ..s2. 4749732.573958: bpf_trace_printk: [add_metadata_to_log] add pkt 1 to ring[0]
          <idle>-0       [008] ..s2. 4749732.575981: bpf_trace_printk: [add_metadata_to_log] add pkt 2 to ring[1]
          <idle>-0       [008] ..s2. 4749732.575986: bpf_trace_printk: [add_metadata_to_log] add pkt 3 to ring[2]
          <idle>-0       [008] ..s2. 4749732.577790: bpf_trace_printk: [add_metadata_to_log] add pkt 4 to ring[3]
          <idle>-0       [008] ..s2. 4749732.577795: bpf_trace_printk: [add_metadata_to_log] add pkt 5 to ring[4]
          <idle>-0       [008] ..s2. 4749732.579515: bpf_trace_printk: [add_metadata_to_log] add pkt 6 to ring[5]
          <idle>-0       [008] ..s2. 4749732.579519: bpf_trace_printk: [add_metadata_to_log] add pkt 7 to ring[6]
          <idle>-0       [008] ..s2. 4749732.581302: bpf_trace_printk: [add_metadata_to_log] add pkt 8 to ring[7]
          <idle>-0       [008] ..s2. 4749732.581306: bpf_trace_printk: [add_metadata_to_log] add pkt 9 to ring[0]
```

Check packet loss recovery of all lost packets on core 8: `grep "\[008\].*loss.*pkt [1-9]" log-1_3.log`
Example output:
```
           <...>-2001359 [008] ..s1. 4750013.159236: bpf_trace_printk: [handle_one_packet_loss] to recover pkt 1
           <...>-2001359 [008] ..s1. 4750013.159240: bpf_trace_printk: [handle_packet_loss] pkt 1 is lost at core 9
           <...>-2001359 [008] ..s1. 4750013.159241: bpf_trace_printk: [handle_packet_loss] pkt 1 lost at all cores. Don't need to recover state
           <...>-2001359 [008] ..s1. 4750013.159242: bpf_trace_printk: [handle_one_packet_loss] recover pkt 1 SUCCEED
           <...>-2001359 [008] ..s1. 4750013.159243: bpf_trace_printk: [handle_one_packet_loss] to recover pkt 2
           <...>-2001359 [008] ..s1. 4750013.159246: bpf_trace_printk: [handle_packet_loss] pkt 2 is lost at core 9
           <...>-2001359 [008] ..s1. 4750013.159247: bpf_trace_printk: [handle_packet_loss] pkt 2 lost at all cores. Don't need to recover state
           <...>-2001359 [008] ..s1. 4750013.159248: bpf_trace_printk: [handle_one_packet_loss] recover pkt 2 SUCCEED
           <...>-2001359 [008] ..s1. 4750013.159249: bpf_trace_printk: [handle_one_packet_loss] to recover pkt 3
           <...>-2001359 [008] ..s1. 4750013.159252: bpf_trace_printk: [handle_packet_loss] get metadata of pkt 3 from core 9
           <...>-2001359 [008] ..s1. 4750013.159254: bpf_trace_printk: [handle_one_packet_loss] recover pkt 3 SUCCEED
```

Check packet loss recovery of pkt 1 on core 8: `grep "\[008\].*loss.*pkt 1" log-1.log`
Example output:
```
          <idle>-0       [008] ..s2. 4749761.234503: bpf_trace_printk: [handle_one_packet_loss] to recover pkt 1
          <idle>-0       [008] ..s2. 4749761.234505: bpf_trace_printk: [handle_packet_loss] get metadata of pkt 1 from core 9
          <idle>-0       [008] ..s2. 4749761.234507: bpf_trace_printk: [handle_one_packet_loss] recover pkt 1 SUCCEED
```



### Parameters
- packet loss rate -> performance

1. correctness
more cores
formal proof of correctness

different packet loss rates: also consider bursty

under low tx rate
under high tx rate
2. performance under different packet loss rates
3. a single .h file for packet loss
