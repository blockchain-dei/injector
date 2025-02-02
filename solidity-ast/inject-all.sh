#!/bin/bash

echo "===================="
echo "= Generating mutations for ${1}"
echo "===================="

# serialize the AST for no-fault scenario, so the format resembles the injected cases
./ast/serializer.py $1 "${1%.*}-0-0.${1##*.}"

#./inject.sh ./ast/remove-varinit.py $1 # 2
#./inject.sh ./ast/remove-assign.py $1 # 4
#./inject.sh ./ast/remove-loopincr.py $1 # 5
#./inject.sh ./ast/remove-loopdecr.py $1 # 6
#./inject.sh ./ast/swap-assignment.py $1 # 11
#./inject.sh ./ast/offbyone-varinit.py $1 # 13
#./inject.sh ./ast/remove-if.py $1 # 24
#./inject.sh ./ast/remove-or-branchcond.py $1 # 25
#./inject.sh ./ast/remove-and-branchcond.py $1 # 26
#./inject.sh ./ast/invert-branchcond.py $1 # 28
#./inject.sh ./ast/swap-arith-branchcond.py $1 # 29
#./inject.sh ./ast/remove-return.py $1 # 31
#./inject.sh ./ast/remove-or-funccall.py $1 # 33
#./inject.sh ./ast/remove-and-funccall.py $1 # 34
#./inject.sh ./ast/invert-funccallcond.py $1 # 36
#./inject.sh ./ast/remove-funccall.py $1 # 43
#./inject.sh ./ast/remove-ifelse.py $1 # 45
#./inject.sh ./ast/remove-iter.py $1 # 48
#./inject.sh ./ast/swap-statements.py $1 # 58
#./inject.sh ./ast/remove-safemath.py $1 # 63
#./inject.sh ./ast/remove-require-input.py $1 # 64
#./inject.sh ./ast/remove-and-req-input.py $1 # 65
#./inject.sh ./ast/remove-or-req-input.py $1 # 66
#./inject.sh ./ast/remove-if-input.py $1 # 67
#./inject.sh ./ast/remove-and-branchcond-input.py $1 # 68
#./inject.sh ./ast/remove-or-branchcond-input.py $1 # 69
#./inject.sh ./ast/invert-require-input.py $1 # 70
#./inject.sh ./ast/invert-branchcond-input.py $1 # 71
#./inject.sh ./ast/remove-require-msgsender.py $1 # 72
#./inject.sh ./ast/remove-and-req-msgsender.py $1 # 73
#./inject.sh ./ast/remove-or-req-msgsender.py $1 # 74
#./inject.sh ./ast/remove-if-msgsender.py $1 # 75
#./inject.sh ./ast/remove-and-branchcond-msgsender.py $1 # 76
#./inject.sh ./ast/remove-or-branchcond-msgsender.py $1 # 77
#./inject.sh ./ast/invert-require-msgsender.py $1 # 78
#./inject.sh ./ast/invert-branchcond-msgsender.py $1 # 79
#./inject.sh ./ast/make-public.py $1 # 80

./inject.sh ./ast/vul-1-1-1.py
./inject.sh ./ast/vul-1-3-1.py
./inject.sh ./ast/vul-1-3-2.py
./inject.sh ./ast/vul-2-1-1.py
./inject.sh ./ast/vul-2-2-2.py
./inject.sh ./ast/vul-3-1.py
./inject.sh ./ast/vul-3-2.py
./inject.sh ./ast/vul-4-1.py
./inject.sh ./ast/vul-4-3.py
./inject.sh ./ast/vul-5-2-1.py
./inject.sh ./ast/vul-5-4-2.py
./inject.sh ./ast/vul-5-6-1.py
./inject.sh ./ast/vul-5-6-2.py
./inject.sh ./ast/vul-5-7-3.py
./inject.sh ./ast/vul-5-8-2.py
./inject.sh ./ast/vul-5-13-1.py
./inject.sh ./ast/vul-6-1-7.py
./inject.sh ./ast/vul-6-2-1.py
./inject.sh ./ast/vul-7-1-1.py
./inject.sh ./ast/vul-7-3-1.py
./inject.sh ./ast/vul-8-1-1.py
./inject.sh ./ast/vul-8-1-2.py
./inject.sh ./ast/vul-8-1-3.py


echo "Done with $1"