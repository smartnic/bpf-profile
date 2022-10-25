import argparse
import shutil

MEASUREMENT_START_FILE = "measure_start.txt"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-o', dest="file_out_path", type=str, help='Output path of measure start file', required=True)
    parser.add_argument('-trex_stats', dest="trex_stats_path", type=str, help='Output path of trex stats', required=True)
    args = parser.parse_args()
    tmp_file = f"{args.file_out_path}/{MEASUREMENT_START_FILE}_tmp"
    f = open(f"{tmp_file}", "w")
    f.writelines(args.trex_stats_path)
    f.close()
    shutil.move(tmp_file, f"{args.file_out_path}/{MEASUREMENT_START_FILE}")
