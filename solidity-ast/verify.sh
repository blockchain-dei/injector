#!/bin/bash

# 1: directory of contracts
# 2: arithmetic mode

echo "ID_contract_filename,FormalResult,assert,loopinv,overflow,contrinv,postcond,modification,reentrancy"
for f in $1; do
    solc-verify.py $f --arithmetic $2 --timeout 300 > tmp.txt
    ret=$?
    base=${f##*/}
    base=${base%.*}
    result="UNKNOWN"
    asserts=$(grep "Assertion might not hold" tmp.txt | wc -l)
    loopinv=$(grep "\(might not hold on loop entry\)\|\(might not be maintained by the loop\)" tmp.txt | wc -l)
    overflow=$(grep "\(An overflow can occur before calling function\)\|\(Function can terminate with overflow\)\|\(no overflow in\)\|\(Invariant 'No overflow' might not hold on loop entry\)" tmp.txt | wc -l)
    inv=$(grep "\(Invariant .* might not hold at end of function\)\|\(Invariant .* might not hold when entering function.\)" tmp.txt | wc -l)
    postcond=$(grep "Postcondition .* might not hold at end of function" tmp.txt | wc -l)
    modif=$(grep "Function might modify" tmp.txt | wc -l)
    reentr=$(grep "might not hold before external call" tmp.txt | wc -l)
    if [[ $ret == 0 ]]
    then
        result="TRUE"
    else
        if [[ $ret == 251 ]]
        then
            result="FALSE"
        fi
    fi
    echo "$base,$result,$asserts,$loopinv,$overflow,$inv,$postcond,$modif,$reentr"
done