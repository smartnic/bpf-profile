import shutil

MEASUREMENT_STOP_FILE = "measure_stop.txt"

if __name__ == "__main__":
    tmp_file = f"{MEASUREMENT_STOP_FILE}_tmp"
    f = open(f"{tmp_file}", "w")
    f.writelines("stop") # the content does not matter
    f.close()
    shutil.move(tmp_file, MEASUREMENT_STOP_FILE)
