# Modified from trex, to also vary UDP dport when running multiple streams
from trex_stl_lib.api import *
from send_udp_packets_portknock import portknock_construct_packets
from send_udp_packets_hhd import hhd_construct_packets
from send_udp_packets_ddos_mitigator import ddos_mitigator_construct_packets
from send_udp_packets_token_bucket import token_bucket_construct_packets
from send_udp_packets_nat_dp import nat_dp_construct_packets
# Tunable example
#
#trex>profile -f stl/udp_for_benchmarks.py
#
#Profile Information:
#
#
#General Information:
#Filename:         stl/udp_for_benchmarks.py
#Stream count:          1
#
#Specific Information:
#Type:             Python Module
#Tunables:         ['stream_count = 1', 'direction = 0', 'packet_len = 64']
#
#trex>start -f stl/udp_for_benchmarks.py -t  packet_len=128 --port 0
#
class STLS1(object):
    '''
    Generalization of udp_1pkt_simple, can specify number of streams and packet length
    '''
    def create_stream (self, actual_packet_len, stream_count, benchmark, version, num_cores, num_flows):
        print(f"[create_stream] actual_packet_len: {actual_packet_len}")
        packets = []
        packet_len = actual_packet_len - 4
        for i in range(num_cores):
            base_pkts = []
            # used for RSS, src mac starts from 10:10:10:10:10:01 (i.e., core 1)
            src_mac = f"10:10:10:10:10:{format(i+1, '02x')}"
            print(f"create_stream: {src_mac}")
            if benchmark == "portknock":
                base_pkts = portknock_construct_packets("loop", version, src_mac, num_cores, packet_len)
            elif benchmark == "hhd":
                base_pkts = hhd_construct_packets(version, src_mac, num_cores, num_flows, packet_len)
            elif benchmark == "ddos_mitigator":
                base_pkts = ddos_mitigator_construct_packets(version, src_mac, num_cores, num_flows, packet_len)
            elif benchmark == "token_bucket":
                base_pkts = token_bucket_construct_packets(version, src_mac, num_cores, num_flows, packet_len)
            elif benchmark == "nat_dp":
                base_pkts = nat_dp_construct_packets(version, src_mac, num_cores, num_flows, packet_len)
            assert(len(base_pkts) > 0)
            for base_pkt in base_pkts:
                base_pkt_len = len(base_pkt)
                print(f"[create_stream] base_pkt_len: {base_pkt_len}")
                base_pkt /= 'x' * max(0, packet_len - base_pkt_len)
                packets.append(STLStream(
                    packet = STLPktBuilder(pkt = base_pkt),
                    # use continuous mode
                    mode = STLTXCont()
                ))
            # if i == 0: # add latency stream (used to measure the latency)
            #     latency_packet = base_pkts[0]
            #     # add additional bytes to be overwritten by trex to measure the latency
            #     # todo: have not figured out how many bytes will be overwritten, 16 is a number
            #     # which works for xdp_hhd
            #     latency_packet /= 'x' * 16
            #     packets.append(STLStream(
            #         packet = STLPktBuilder(pkt = latency_packet),
            #         mode = STLTXCont(pps=1000),
            #         flow_stats = STLFlowLatencyStats(pg_id = stream_count + 1)
            #     ))
        return packets
    def get_streams (self, direction = 0, packet_len = 64, stream_count = 1, **kwargs):
        # create 1 stream
        return self.create_stream(
            kwargs['kwargs']['packet_len'],
            stream_count,
            kwargs['kwargs']['benchmark'],
            kwargs['kwargs']['version'],
            kwargs['kwargs']['num_cores'],
            kwargs['kwargs']['num_flows'])
# dynamic load - used for trex console or simulator
def register():
    return STLS1()
