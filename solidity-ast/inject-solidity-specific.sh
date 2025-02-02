#!/bin/bash

echo "===================="
echo "= Generating mutations for ${1}"
echo "===================="

serialized_file="${1%.*}-0-0.json"

# serialize the AST for no-fault scenario, so the format resembles the injected cases
./ast/serializer.py $1 "$serialized_file"

# Assignment faults
#./inject.sh ./ast/A_MISP.py $1
#./inject.sh ./ast/A_MILV.py $1
#./inject.sh ./ast/A_MISV.py $1
#./inject.sh ./ast/A_MISV_2.py $1
#./inject.sh ./ast/A_MC.py $1
#./inject.sh ./ast/A_MCV.py $1
#./inject.sh ./ast/A_WVAE.py $1
#./inject.sh ./ast/A_WIS.py $1
#./inject.sh ./ast/A_WIS_2.py $1
#./inject.sh ./ast/A_WIT.py $1
#./inject.sh ./ast/A_WVATMD.py $1
#./inject.sh ./ast/A_WVATMD_2.py $1
#./inject.sh ./ast/A_WVAA.py $1
#./inject.sh ./ast/A_WVAA_2.py $1
#./inject.sh ./ast/A_WCN.py $1
#./inject.sh ./ast/A_WVT.py $1
#./inject.sh ./ast/A_WDISV.py $1
#./inject.sh ./ast/A_WVN.py $1
#./inject.sh ./ast/A_WFTVA.py $1

#./inject.sh ./ast/CH_MRTS.py $1
#./inject.sh ./ast/CH_MRIV.py $1
#./inject.sh ./ast/CH_MROTS.py $1
#./inject.sh ./ast/CH_MROIV.py $1
#./inject.sh ./ast/CH_MRATS.py $1
#./inject.sh ./ast/CH_MRAIV.py $1
#./inject.sh ./ast/CH_MCHGL.py $1


#./inject.sh ./ast/CH_MCHRV.py $1
#./inject.sh ./ast/CH_MCHAO.py $1
#./inject.sh ./ast/CH_MCHSF.py $1
#./inject.sh ./ast/CH_WRA.py $1
#./inject.sh ./ast/I_MVMSV.py $1
#./inject.sh ./ast/I_MFVM.py $1
#./inject.sh ./ast/I_WVPF.py $1
#./inject.sh ./ast/AL_MITSS.py $1
#./inject.sh ./ast/AL_MIIVS.py $1
#./inject.sh ./ast/AL_WRAR.py $1
#./inject.sh ./ast/AL_WEH.py $1
#./inject.sh ./ast/AL_ECSWS.py $1
#./inject.sh ./ast/F_MWF.py $1
#./inject.sh ./ast/F_MINHERITANCE.py $1
#./inject.sh ./ast/F_WIO.py $1
#./inject.sh ./ast/F_EINHERITANCE.py $1


#./inject.sh ./ast/A_WBSAVF.py $1
#./inject.sh ./ast/A_WBSAVF_2.py $1

./inject.sh ./ast/vul-1-1-1.py $1
./inject.sh ./ast/vul-1-3-1.py $1
./inject.sh ./ast/vul-1-3-2.py $1
./inject.sh ./ast/vul-2-1-1.py $1
./inject.sh ./ast/vul-2-2-2.py $1
./inject.sh ./ast/vul-3-1.py $1
./inject.sh ./ast/vul-3-2.py $1
./inject.sh ./ast/vul-4-1.py $1
./inject.sh ./ast/vul-4-3.py $1
./inject.sh ./ast/vul-5-2-1.py $1
./inject.sh ./ast/vul-5-4-2.py $1
./inject.sh ./ast/vul-5-6-1.py $1
./inject.sh ./ast/vul-5-6-2.py $1
./inject.sh ./ast/vul-5-7-3.py $1
./inject.sh ./ast/vul-5-8-2.py $1
./inject.sh ./ast/vul-5-13-1.py $1
./inject.sh ./ast/vul-6-1-7.py $1
./inject.sh ./ast/vul-6-2-1.py $1
./inject.sh ./ast/vul-7-1-1.py $1
./inject.sh ./ast/vul-7-3-1.py $1
./inject.sh ./ast/vul-8-1-1.py $1
./inject.sh ./ast/vul-8-1-2.py $1
./inject.sh ./ast/vul-8-1-3.py $1


echo "Done with $1"
