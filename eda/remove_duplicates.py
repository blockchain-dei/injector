import os
import glob
import argparse


def load_file(file):
    with open(file, 'r') as f:
        return f.read()


#################
# CLI INTERFACE #
#################
parser = argparse.ArgumentParser(description='Removes duplicate files with same content in the given directory')

parser.add_argument('input', help='the directory to search')
args = parser.parse_args()

content_file_map = {}

file_pattern = '{0}/*'.format(args.input)
input_files = glob.glob(file_pattern, recursive=False)

for file in input_files:
    content = load_file(file)

    if content not in content_file_map:
        content_file_map[content] = []

    content_file_map[content].append(os.path.basename(file))

duplicates = 0

for value in content_file_map.values():
    if len(value) > 1:
        duplicates += len(value) - 1
        for i in range(len(value)):
            if i > 0:
                os.remove(args.input+value[i])

print(f'{duplicates} duplicate removed')