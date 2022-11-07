from config import vt_keys
from VTChecker import VTChecker
from pe_parser import write_pe_structure

import argparse
from datetime import datetime
import hashlib
import os
import pyminizip
import subprocess
import sys

DATE = datetime.now().strftime("%m-%d-%Y-%H%M%S")

def get_input_args():
    parser = argparse.ArgumentParser(
        description="Performs static analysis on all files in a directory.",
        usage=f"python3 {sys.argv[0]} <path_to_samples>"
    )

    parser.add_argument('samples_path', type=str,
                        help='Path to samples directory')

    return parser.parse_args()

def starts_with_mz(filename):
    try:
        with open(filename, 'rb') as f:
            return f.read(2) == 'MZ'
    except:
        return False


class KeyRot:
    def __init__(self, arr):
        self.arr = arr
        self.i = 0

    def __next__(self):
        el = self.arr[self.i % len(self.arr)]
        self.i += 1
        return el


def flarestrings(file_path, out_dir, n=7):
    flare = ["flarestrings", f"-n {n}", file_path]
    fp = subprocess.Popen(flare, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    rank = ["rank_strings", "--scores"]
    with open(f"{out_dir}\\ranked_strings.out", "w") as f:
        subprocess.run(rank, stdin=fp.stdout, stdout=f, stderr=subprocess.DEVNULL)

def floss(file_path, out_dir, n=7):
    cmd = ["floss", f"-n {n}", file_path]
    with open(f"{out_dir}\\floss_out.txt", 'w') as f:
        subprocess.run(cmd, stdout=f)

def hashes(filename, out_file):
    BUF_SIZE = 65536

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    with open(out_file, 'w') as f:
        f.write("MD5: " + md5.hexdigest() + '\n')
        f.write("SHA1: " + sha1.hexdigest() + '\n')
        f.write("SHA256: " + sha256.hexdigest() + '\n')

def cleanup(sample_path, name, out_dir):
    zip_name = out_dir + "\\" + name + ".zip"
    passwd = "infected"
    pyminizip.compress(sample_path, None, zip_name, passwd, 5)
    if os.path.exists(zip_name):
        os.remove(sample_path)   

if __name__ == "__main__":
    keys = KeyRot(vt_keys)
    path = get_input_args().samples_path
    files = os.listdir(path)
    if not files:
        print(f"No samples found at {path}")
        exit()

    for file in files:
        sample_path = path + "\\" + file
        results_dir = file.replace(".", "-") + DATE
        os.system("mkdir " + results_dir)
        
        if starts_with_mz(sample_path):
            write_pe_structure(sample_path, results_dir)

        hashes(sample_path, f"{results_dir}\\hashes.txt")
        VTChecker(f"{results_dir}\\hashes.txt", f"{results_dir}\\vt_out.txt", keys, {"HASH"}).drive()

        flarestrings(sample_path, results_dir)
        floss(sample_path, results_dir)
        VTChecker(f"{results_dir}\\floss_out.txt", f"{results_dir}\\vt_out.txt", keys, {"URL", "IPv4"}).drive()

        try:
            cleanup(sample_path, results_dir, results_dir)
        except:
            print(f"Error cleaning up {sample_path}")
