#!/bin/bash

cd "$1"

zip -r -q outputs.zip ./outputs
zip -r -q logs.zip ./logs

zip -q "MERGED.zip" "MERGED.csv"
zip -q "MERGED_DEBUG.zip" "MERGED_DEBUG.csv"