Generate pcap files where `dport_list = [PORT_1, PORT_2, PORT_3, PORT_1, PORT_1, PORT_1, PORT_1]`
```
python3 gen_pcap_portknock.py
sudo python3 ../../pcap_scripts/gen_pcap_versions.py --config gen_pcap.yaml
sudo chown -R qx51 192
cp 192/xdp_portknock_shared_nothing_pkt_loss_2.pcap lost-0.pcap
editcap -r -v lost-0.pcap lost-1.pcap 2-7
editcap -r -v lost-0.pcap lost-2.pcap 1 3-7
editcap -r -v lost-0.pcap lost-3_5.pcap 1-2 6-7
```

Check state update on core 8: `grep "\[008\].* state " log-0.log`

Example output 
```
          <idle>-0       [008] ..s2. 4779131.291036: bpf_trace_printk: [update_state_by_metadata] insert state 1 for src ip 6401a8c0
          <idle>-0       [008] ..s2. 4779131.293098: bpf_trace_printk: [update_state_by_metadata] new state 2 for src ip 6401a8c0
          <idle>-0       [008] ..s2. 4779131.293101: bpf_trace_printk: [update_state_by_metadata] new state 3 for src ip 6401a8c0
          <idle>-0       [008] ..s2. 4779131.294814: bpf_trace_printk: [update_state_by_metadata] new state 0 for src ip 6401a8c0
          <idle>-0       [008] ..s2. 4779131.294817: bpf_trace_printk: [update_state_by_metadata] new state 1 for src ip 6401a8c0
          <idle>-0       [008] ..s2. 4779131.296364: bpf_trace_printk: [update_state_by_metadata] new state 0 for src ip 6401a8c0
          <idle>-0       [008] ..s2. 4779131.296368: bpf_trace_printk: [update_state_by_metadata] remove state 1 for src ip 6401a8c0
```