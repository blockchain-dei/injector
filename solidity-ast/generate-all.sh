#!/bin/bash

rm -rf out
rm -rf ./../contracts

# DISABLE WORKLOAD GENERATION
rm -rf ./../tests/workloads/
rm -f ./../metadata/contracts.csv

mkdir out
mkdir -p ./../contracts/src
mkdir -p ./../contracts/bytecode
mkdir -p ./../contracts/abi

for f in examples/${1:-*}.sol; do
    ./inject-all.sh $f
    # DISABLE WORKLOAD GENERATION
    ./ast/testgen.py $f
done
./create-csv.py ./../contracts/src/ > ./../metadata/contracts.csv

# DISABLE WORKLOAD GENERATION
mkdir -p ./../tests/workloads/
mv examples/*.js ./../tests/workloads/