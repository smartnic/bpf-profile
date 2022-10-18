# Modified from trex, to also vary UDP dport when running multiple streams
from trex_stl_lib.api import *
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
    def create_stream (self, packet_len, stream_count):
        packets = []
        for i in range(stream_count):
            # base_pkt = Ether()/IP(src="16.0.0.1",dst="10.70.2.2")/UDP(dport=12+i,sport=1025)
            base_pkt = Ether(src="9c:dc:71:5d:e5:31",dst="9c:dc:71:49:a8:91")/IP(src="10.10.1.1",dst="10.10.1.2")/UDP(dport=12+i,sport=1025)
            base_pkt_len = len(base_pkt)
            base_pkt /= 'x' * max(0, packet_len - base_pkt_len)
            packets.append(STLStream(
                packet = STLPktBuilder(pkt = base_pkt),
                # use continuous mode
                mode = STLTXCont()
            ))
            if i == 0: # add latency stream (used to measure the latency)
                packets.append(STLStream(
                    packet = STLPktBuilder(pkt = base_pkt),
                    mode = STLTXCont(pps=1000),
                    flow_stats = STLFlowLatencyStats(pg_id = stream_count + 1)
                ))
        return packets
    def get_streams (self, direction = 0, packet_len = 64, stream_count = 1, **kwargs):
        # create 1 stream
        return self.create_stream(packet_len - 4, stream_count)
# dynamic load - used for trex console or simulator
def register():
    return STLS1()
