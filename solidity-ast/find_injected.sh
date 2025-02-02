#!/bin/bash
search_dir=/Users/fernandovidal/all_contracts/
for entry in "$search_dir"/*
do
     orig=${entry%-*}
     orig=${orig%-*}
     orig="$orig-0-0.sol";
     echo "$orig"
     echo "$entry"
     ./find_injected_line.py "$orig" "$entry"  >> injected_lines.csv
done
    