#!/bin/bash

for sol in examples/*.sol serializer-test/*.sol; do
    echo -n "- $sol: "
    DIR=$(dirname "${sol}")
    solc --ast-json -o $DIR/ --overwrite $sol 2> /dev/null
    ./ast/serializer.py "${sol}_json.ast" "${sol}_ser"
    solc --asm $sol > $DIR/bin1.evm 2> /dev/null
    solc --asm "${sol}_ser" > $DIR/bin2.evm 2> /dev/null
    sed -i  "/^\s*\/\*.*\*\/$/d" $DIR/bin1.evm
    sed -i  "/^\s*\/\*.*\*\/$/d" $DIR/bin2.evm
    sed -i  "/auxdata: /d" $DIR/bin1.evm
    sed -i  "/auxdata: /d" $DIR/bin2.evm
    sed -i  "/====== /d" $DIR/bin1.evm
    sed -i  "/====== /d" $DIR/bin2.evm
    cmp -s $DIR/bin1.evm $DIR/bin2.evm
    if [[ "$?" == "0" ]] 
    then
        echo -e "OK"
    else
        echo -e "ERROR"
    fi
done

rm examples/*.sol_json.ast
rm examples/*.sol_ser
rm examples/*.evm

rm serializer-test/*.sol_json.ast
rm serializer-test/*.sol_ser
rm serializer-test/*.evm
