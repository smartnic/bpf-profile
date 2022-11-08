import argparse
import shutil

MEASUREMENT_STOP_FILE = "measure_stop.txt"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-o', dest="file_out_path", type=str, help='Output path of measure stop file', required=True)
    args = parser.parse_args()
    tmp_file = f"{args.file_out_path}/{MEASUREMENT_STOP_FILE}_tmp"
    f = open(f"{tmp_file}", "w")
    f.writelines("stop") # the content does not matter
    f.close()
    shutil.move(tmp_file, f"{args.file_out_path}/{MEASUREMENT_STOP_FILE}")
