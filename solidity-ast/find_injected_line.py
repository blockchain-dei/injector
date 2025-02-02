#!/usr/bin/env python3
import argparse
import os

parser = argparse.ArgumentParser(description='Get the lines where the injections occured by checking the source code difference.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('file1', type=str, help='Path to the original Solidity (.sol) file')
parser.add_argument('file2', type=str, help='Path to the injected Solidity (.sol) file')
args = parser.parse_args()

with open(args.file2, 'r') as file1, open(args.file1, 'r') as file2:
    i = 1
    for line1, line2 in zip(file1, file2):
        if line1 != line2:
            print(os.path.basename(args.file2) + ";" + str(i) + ";" + line1.replace("\n", "").strip())
           # print(os.path.basename(args.file1) + ";" + str(i) + ";" + line2.replace("\n", "").strip())
            
            break
        else: i = i + 1