from trex_stl_lib.api import *
import time
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-b', dest="benchmark", type=str, help='Name of the BPF program', required=True)
    parser.add_argument('-v', dest="version", type=str, help='Name of version (e.g v1, v2, v3)', required=True)
    parser.add_argument('-t', dest="time", type=int, help='How long(secs) you want to send packets', default=100)
    parser.add_argument('-r', dest="rate", type=float, help='Multiplier send rate in Mpps', default=1)
    args = parser.parse_args()

    c = STLClient(server='127.0.0.1')
    rate = args.rate
    try:
        c.connect() # connect to server
        c.reset(ports = 0)
        c.add_profile(filename="stl/udp_for_benchmarks.py", ports=0, 
            kwargs={"packet_len": 64, "stream_count": 1, "benchmark": args.benchmark, "version": args.version})
        # Need to specify 'force', or add the destination mac address in /etc/trex_cfg.yaml
        # otherwise, not able to send packets (cannot pass the start check)
        c.start(ports = 0, duration = args.time, mult=f"{rate}mpps", force=True)
        time.sleep(0.5)
        print(f"Start: {rate}")
        while (True):
            stats = c.get_stats()
            print(stats)
            time.sleep(2)
    except STLError as e:
        print(e)

    finally:
        c.disconnect()
        time.sleep(10)
