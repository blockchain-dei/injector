#!/bin/bash

function abs_path() {
    echo "$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"
}

function file_count() {
    ls -1q "$1" | wc -l
}

function collect_cc_logs() {
    # 1. docker logs: retrieve CC logs
    # 2. grep: keep only the line related to custom TX data (which looks like <<MONITOR>>DATA<<MONITOR>>)
    # 3. 1st sed: keep only the DATA part of the lines
    # 4. 2nd sed: rename the evm_time data variable to denote the source peer
    # 5. 3rd sed: rename the evmcc_time data variable to denote the source peer
    # 6. save the result to a file
    docker logs dev-peer0.org${1}.example.com-evmcc-v0 2>&1 | grep -a '' >> "${LOG_FILE}_raw_org${1}.log"
    cat "${LOG_FILE}_raw_org${1}.log" | grep -a "<<MONITOR>>" | sed 's/^.*<<MONITOR>>\(.*\)<<MONITOR>>.*$/\1/' | sed "s/duration_ns_evm/duration_ns_evm_peer0.org${1}.example.com/" | sed "s/duration_ns_cc/duration_ns_cc_peer0.org${1}.example.com/" | sed "s/cc_start_epoch_ns/cc_start_epoch_ns_peer0.org${1}.example.com/" | sed "s/evm_start_epoch_ns/evm_start_epoch_ns_peer0.org${1}.example.com/" | sed "s/evm_end_epoch_ns/evm_end_epoch_ns_peer0.org${1}.example.com/" | sed "s/cc_end_epoch_ns/cc_end_epoch_ns_peer0.org${1}.example.com/" >> ${LOG_FILE}
}

CALIPER_DIR_NAME=caliper-evm
CALIPER_DIR="./../../../${CALIPER_DIR_NAME}"

CONTRACTS_DIR="./../../contracts/src"
INPUT_FILES=(`ls -v ${CONTRACTS_DIR}/*.sol`)
OUTPUT_BASE_DIR="./../../eda"

CAMPAIGN_DIR=${1-`date +%F_%H-%M`}
OUTPUT_DIR="${OUTPUT_BASE_DIR}/${CAMPAIGN_DIR}"

if [[ -d "${OUTPUT_DIR}" ]]
then
    echo "Campaign directory already exists"
    exit 1
fi

NODE_INDEX=${NODE_INDEX-0}
NUMBER_OF_NODES=${NUMBER_OF_NODES-1}

if [[ ${NODE_INDEX} -ge ${NUMBER_OF_NODES} ]]
then
    echo "Node index (${NODE_INDEX}) must be less than the number of nodes (${NUMBER_OF_NODES})"
    exit 1
fi

LAST_INDEX=$((NUMBER_OF_NODES - 1))

TOTAL_NUMBER_OF_CONTRACTS=`file_count ${CONTRACTS_DIR}`
CONTRACTS_PER_NODE=$((TOTAL_NUMBER_OF_CONTRACTS / NUMBER_OF_NODES))
REMAINING_CONTRACTS=$((TOTAL_NUMBER_OF_CONTRACTS % NUMBER_OF_NODES))

FIRST_CONTRACT_INDEX_INCLUSIVE=$((NODE_INDEX * CONTRACTS_PER_NODE))

# an extra contract is given, if the node index is less than the remaining contracts
# if this node gets an extra contract, shift its start index, and increment its contract per node number
# this means every node before it had an extra contract
# the index must be shifted by the number of nodes before this node, which is exactly its index
if [[ ${NODE_INDEX} -lt ${REMAINING_CONTRACTS} ]]
then
    CONTRACTS_PER_NODE=$((CONTRACTS_PER_NODE + 1))
    FIRST_CONTRACT_INDEX_INCLUSIVE=$((FIRST_CONTRACT_INDEX_INCLUSIVE + NODE_INDEX))
fi

# if the node didn't get an extra contract, then just shift its start index by the number of remaining contracts
if [[ ${NODE_INDEX} -ge ${REMAINING_CONTRACTS} ]]
then
    FIRST_CONTRACT_INDEX_INCLUSIVE=$((FIRST_CONTRACT_INDEX_INCLUSIVE + REMAINING_CONTRACTS))
fi

LAST_CONTRACT_INDEX_EXCLUSIVE=$((FIRST_CONTRACT_INDEX_INCLUSIVE + CONTRACTS_PER_NODE))

echo "====== INFO ======"
echo "Campaign name: ${CAMPAIGN_DIR}"
echo "Output directory: `abs_path ${OUTPUT_DIR}`"
echo "Caliper directory: `abs_path ${CALIPER_DIR}`"
echo "Contracts directory: `abs_path ${CONTRACTS_DIR}`"
echo "Total number of contracts: ${TOTAL_NUMBER_OF_CONTRACTS}"
echo "Node index: ${NODE_INDEX}"
echo "Number of nodes: ${NUMBER_OF_NODES}"
echo "Contracts for this node: ${CONTRACTS_PER_NODE}"
echo "First contract index (inclusive): ${FIRST_CONTRACT_INDEX_INCLUSIVE}"
echo "Last contract index (exclusive): ${LAST_CONTRACT_INDEX_EXCLUSIVE}"


mkdir ${OUTPUT_DIR}
mkdir ${OUTPUT_DIR}/logs
mkdir ${OUTPUT_DIR}/outputs

echo "Cleaning up Caliper output remnants"
rm -rf ./caliper/outputs
mkdir ./caliper/outputs
rm -f ./caliper/*.log
rm -f ./caliper/*.csv

# evaluate "ls" to empty list when files not found (i.e., no variant was generated)
shopt -s nullglob

for ((i=${FIRST_CONTRACT_INDEX_INCLUSIVE}; i<${LAST_CONTRACT_INDEX_EXCLUSIVE}; i++)); do
    FILE_PATH="${INPUT_FILES[$i]}"
    FILE_NAME=$(basename -- "$FILE_PATH") # e.g., BecToken-0-0.sol
    FILE_NAME_NO_EXT=${FILE_NAME%.*} # e.g., BecToken-0-0

    echo "====== ${FILE_NAME} ($((i + 1))/${CONTRACTS_PER_NODE})======"

    LOG_DIR=${OUTPUT_DIR}/logs/${FILE_NAME_NO_EXT}
    mkdir ${LOG_DIR}

    # generate the config files
    node ./caliper/genconfigs.js ${FILE_NAME_NO_EXT}

    # starting network
    docker-compose -f fabric/docker-compose-tls.yaml up -d
    #docker compose -f fabric/docker-compose-tls.yaml up -d -> FOR NEWER VERSIONS OF DOCKER COMPOSER
    sleep 5s
    
    # switching to Caliper dir and running Caliper
    cd ${CALIPER_DIR}

    npm run bench -- -c ./../smartcontract-faultinjection/tests/local-test/caliper/test-config.yaml -n ./../smartcontract-faultinjection/tests/local-test/caliper/network-config.yaml

    #rm -f report*.html

    # switching back to this dir
    cd ./../smartcontract-faultinjection/tests/local-test

    echo "Gathering Caliper logs"

    mv ./caliper/outputs/* ${OUTPUT_DIR}/outputs/
    mv ${CALIPER_DIR}/log/* ${LOG_DIR}/
    mv ${CALIPER_DIR}/report*.html ${LOG_DIR}/

    # prepare empty CSV for TX logs
    LOG_FILE=${FILE_NAME_NO_EXT}.cc.csv
    > ${LOG_FILE}

    echo "Gathering CC logs"

    collect_cc_logs "1"
    collect_cc_logs "2"

    echo "Gathering container logs"

    docker logs orderer.example.com 2>&1 | grep -a '' >> ${LOG_DIR}/orderer.log
    docker logs peer0.org1.example.com 2>&1 | grep -a '' >> ${LOG_DIR}/peer0org1.log
    docker logs peer0.org2.example.com 2>&1 | grep -a '' >> ${LOG_DIR}/peer0org2.log

    # shutting down network
    docker-compose -f fabric/docker-compose-tls.yaml down
    #docker compose -f fabric/docker-compose-tls.yaml down -> FOR NEWER VERSIONS OF DOCKER COMPOSER
    docker rm -f $(docker ps -aq)
    docker rmi $(docker images --filter reference='dev-peer*' -q)

    if [[ -s ./${LOG_FILE} ]]
    then
       echo "Moving CC logs"

        mv ./${LOG_FILE} ${OUTPUT_DIR}/outputs/${LOG_FILE}
        mv ./"${LOG_FILE}_raw_org1.log" ${LOG_DIR}/"${LOG_FILE}_raw_org1.log"
        mv ./"${LOG_FILE}_raw_org2.log" ${LOG_DIR}/"${LOG_FILE}_raw_org2.log"
    else
        echo "${FILE_NAME_NO_EXT}" >> ${OUTPUT_DIR}/node_${NODE_INDEX}_retries.txt
    fi

    sleep 5s
done

exit 0