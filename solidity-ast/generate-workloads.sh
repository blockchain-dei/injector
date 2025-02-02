#!/bin/bash

rm -rf ./../tests/workloads/

for f in examples/${1:-*}.sol; do
    ./ast/testgen.py $f
done

mv examples/*.js ./../tests/workloads/