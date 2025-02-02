#!/bin/bash

rm -rf out
rm -rf ./../contracts

# WORKLOAD GENERATION
rm -rf ./../tests/workloads/
rm -f ./../metadata/contracts.csv

mkdir out
mkdir -p ./../contracts/src
mkdir -p ./../contracts/bytecode
mkdir -p ./../contracts/abi

for f in examples/${1:-*}.sol; do
    if [ ! -f "$f" ]; then
        echo "Nessun file .sol trovato nella directory examples."
        exit 1
    fi
    ./inject-solidity-specific.sh $f
    echo "===================="
    echo "= Generating workload for ${f}"
    echo "===================="
    ./ast/testgen.py $f --limit 1500
done

./create-csv.py ./../contracts/src/ > ./../metadata/contracts.csv

# WORKLOAD GENERATION
mkdir -p ./../tests/workloads/
mv examples/*.js ./../tests/workloads/