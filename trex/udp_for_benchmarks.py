# Modified from trex, to also vary UDP dport when running multiple streams
from trex_stl_lib.api import *
from send_udp_packets_portknock import portknock_construct_packets
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
    def create_stream (self, packet_len, stream_count, benchmark, version, num_cores):
        packets = []
        for i in range(num_cores):
            base_pkts = []
            # used for RSS, src ip starts from 10.10.1.1 (i.e., core 1)
            src_ip = f"10.10.1.{i+1}"
            print(f"create_stream: {src_ip}")
            if benchmark == "portknock":
                base_pkts = portknock_construct_packets("loop", version, src_ip, num_cores)
            assert(len(base_pkts) > 0)
            for base_pkt in base_pkts:
                base_pkt_len = len(base_pkt)
                base_pkt /= 'x' * max(0, packet_len - base_pkt_len)
                packets.append(STLStream(
                    packet = STLPktBuilder(pkt = base_pkt),
                    # use continuous mode
                    mode = STLTXCont()
                ))
            if i == 0: # add latency stream (used to measure the latency)
                packets.append(STLStream(
                    packet = STLPktBuilder(pkt = base_pkts[0]),
                    mode = STLTXCont(pps=1000),
                    flow_stats = STLFlowLatencyStats(pg_id = stream_count + 1)
                ))
        return packets
    def get_streams (self, direction = 0, packet_len = 64, stream_count = 1, **kwargs):
        # create 1 stream
        return self.create_stream(packet_len - 4, stream_count,
            kwargs['kwargs']['benchmark'],
            kwargs['kwargs']['version'],
            kwargs['kwargs']['num_cores'])
# dynamic load - used for trex console or simulator
def register():
    return STLS1()
