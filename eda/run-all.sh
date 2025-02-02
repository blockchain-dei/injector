#!/bin/bash

python merge.py "${1}outputs/" -v "${1}formal/" -o "${1}"
python aggregate.py "${1}MERGED.csv"
python matrix.py "${1}AGGREGATED.csv"
python sankey.py "${1}AGGREGATED.csv"
./archive.sh "${1}"