import argparse
import shutil

MEASUREMENT_START_FILE = "measure_start.txt"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Information about Data')
    parser.add_argument('-o', dest="output_path", type=str, help='Output path', required=True)
    args = parser.parse_args()
    tmp_file = f"{MEASUREMENT_START_FILE}_tmp"
    f = open(f"{tmp_file}", "w")
    f.writelines(args.output_path)
    f.close()
    shutil.move(tmp_file, MEASUREMENT_START_FILE)
