#!/bin/bash

# script name, filename
eval "$1" "$2"

pattern="vul/${2%.*}"_*_vul_*"-"*.sol
#echo "Pattern calcolato: $pattern"

# evaluate "ls" to empty list when files not found (i.e., no variant was generated)
shopt -s nullglob

# Percorso del file originale
original_file="$2"
original_name="$(basename $original_file .sol)"
original_path="./${original_file}" # Percorso aggiornato per i file originali
#echo "Pattern 1: $original_file"
#echo "Pattern 2: $original_name"
#echo "Pattern 3: $original_path"

for sol in $pattern; do
    # generate bytecode and ABI into current (out) dir
    solc --output-dir ./out/ --bin --abi "${sol}" --overwrite > /dev/null 2>&1
    #echo "------->: $sol"
    if [[ "$?" != "0" ]]; then
        echo "Compile error for $sol -> deleted"
        rm -f "${sol}"
        rm -rf ./out/*
    else
        # delete other contract files (if the source contains multiple contracts)
        VARIANT_CONTRACT_FILE_NAME="$(basename "${sol}")"
        VARIANT_CONTRACT_NAME="${VARIANT_CONTRACT_FILE_NAME%.*}"

        echo "Sposto il file sorgente: $sol in ./../contracts/src/${VARIANT_CONTRACT_FILE_NAME}"
        mv "${sol}" ./../contracts/src/${VARIANT_CONTRACT_FILE_NAME}

        # change the extension to .json, so nodejs "require" can load it
        mv "./out/${original_name}.abi" "./../contracts/abi/${VARIANT_CONTRACT_NAME}.json"
        mv "./out/${original_name}.bin" "./../contracts/bytecode/${VARIANT_CONTRACT_NAME}.bin"

        rm -rf ./out/*

        # script for comparing the two files and finding the lines where the injection occured
        variant_path="./../contracts/src/${VARIANT_CONTRACT_FILE_NAME}"

        #echo "Pattern 4: $VARIANT_CONTRACT_FILE_NAME"
        #echo "Pattern 5: $VARIANT_CONTRACT_NAME"
        #echo "Pattern 6: $variant_path"

        #echo "Confronto: $original_path e $variant_path"
        ./find_injected_line.py "$original_path" "$variant_path" >> ./../metadata/injected_lines.csv
    fi
done
