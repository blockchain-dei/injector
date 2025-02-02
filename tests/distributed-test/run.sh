#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Missing 1st argument: IP exporter script path"
    exit 1
fi

source "$1"

#############################
# Start container functions #
#############################

start_orderer() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} 'cd orderer;docker-compose up -d'
}

start_p0o1() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} 'cd peer0org1;docker-compose up -d'
}

start_p0o2() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} 'cd peer0org2;docker-compose up -d'
}

start_influxdb() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} 'cd prometheus;docker-compose up -d influxdb grafana'
}

start_prometheus() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} 'cd prometheus;docker-compose up -d prometheus'
}

#############################
# Stop containers functions #
#############################

stop_orderer() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} 'cd orderer && { docker-compose down;docker rm -f $(docker ps -aq); }'
}

stop_p0o1() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} 'cd peer0org1 && { docker-compose down;docker rm -f $(docker ps -aq);docker rmi -f $(docker images dev* -q); }'
}

stop_p0o2() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} 'cd peer0org2 && { docker-compose down;docker rm -f $(docker ps -aq);docker rmi -f $(docker images dev* -q); }'
}

stop_prometheus() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} 'cd prometheus && { docker stop prometheus; docker rm -f prometheus; }'
}

stop_monitoring() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} 'cd prometheus && { docker-compose down;docker rm -f $(docker ps -aq); }'
}

stop_fabric_nodes() {
    stop_p0o1
    stop_p0o2
    stop_orderer
}

#####################
# Utility functions #
#####################

clean_artifacts() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP} 'rm -rf ./caliper-vm'
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} 'rm -rf ./orderer'
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} 'rm -rf ./peer0org1'
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} 'rm -rf ./peer0org2'
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} 'rm -rf ./prometheus'

    rm -rf ./remote
}

backup_influxdb() {
    influxd backup -portable -host ${PROMETHEUS_IP}:8088 -database Fabric ./influxdb \
        && tar -zcf ./influxdb.tar.gz influxdb \
        && rm -rf ./influxdb \
        && mv ./influxdb.tar.gz ${OUTPUT_DIR}/influxdb.tar.gz
}

merge_results() {
    cd ${OUTPUT_BASE_DIR}
    python ./tx-data-merge.py "./dist_${CAMPAIGN_DATE}/outputs/" -o "dist_${CAMPAIGN_DATE}/MERGED.csv"
    # ./merge.sh "dist_${CAMPAIGN_DATE}/outputs/" "dist_${CAMPAIGN_DATE}/MERGED.csv"
    cd ./../tests/distributed-test/
}

compress_results() {
    cd ${OUTPUT_DIR}

    tar -zcf ./logs.tar.gz logs && rm -rf ./logs
    tar -zcf ./outputs.tar.gz outputs && rm -rf ./outputs

    cd ./../../tests/distributed-test/
}

# $2: org index
get_cc_log() {
    # 1. docker logs: retrieve CC logs
    # 2. grep: keep only the line related to custom TX data (which looks like <<MONITOR>>DATA<<MONITOR>>)
    # 3. 1st sed: keep only the DATA part of the lines
    # 4. 2nd sed: rename the duration_ns_evm data variable to denote the source peer
    # 5. 3rd sed: rename the duration_ns_cc variable to denote the source peer
    # 6. save the result to a file
    #ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${1} "docker logs dev-peer0.org$2.example.com-evmcc-v0" 2>&1 | grep "<<MONITOR>>" | sed 's/^.*<<MONITOR>>\(.*\)<<MONITOR>>.*$/\1/' | sed "s/duration_ns_evm/duration_ns_evm_peer0.org$2.example.com/" | sed "s/duration_ns_cc/duration_ns_cc_peer0.org$2.example.com/" >> ${LOG_FILE}
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${1} "docker logs dev-peer0.org$2.example.com-evmcc-v0" 2>&1 | grep '' >> "${LOG_FILE}_raw_org${2}.log"
    cat "${LOG_FILE}_raw_org${2}.log" | grep "<<MONITOR>>" | sed 's/^.*<<MONITOR>>\(.*\)<<MONITOR>>.*$/\1/' | sed "s/duration_ns_evm/duration_ns_evm_peer0.org$2.example.com/" | sed "s/duration_ns_cc/duration_ns_cc_peer0.org$2.example.com/" | sed "s/cc_start_epoch_ns/cc_start_epoch_ns_peer0.org$2.example.com/" | sed "s/evm_start_epoch_ns/evm_start_epoch_ns_peer0.org$2.example.com/" | sed "s/evm_end_epoch_ns/evm_end_epoch_ns_peer0.org$2.example.com/" | sed "s/cc_end_epoch_ns/cc_end_epoch_ns_peer0.org$2.example.com/" >> ${LOG_FILE}

}

get_fabric_docker_logs() {
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} 'docker ps -a' 2>&1 | grep '' >> ${LOG_DIR}/dockerps-orderer.log
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} 'docker ps -a' 2>&1 | grep '' >> ${LOG_DIR}/dockerps-peer0org1.log
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} 'docker ps -a' 2>&1 | grep '' >> ${LOG_DIR}/dockerps-peer0org2.log

    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} 'docker logs orderer.example.com' 2>&1 | grep '' >> ${LOG_DIR}/orderer.log
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} 'docker logs peer0.org1.example.com' 2>&1 | grep '' >> ${LOG_DIR}/peer0org1.log
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} 'docker logs peer0.org2.example.com' 2>&1 | grep '' >> ${LOG_DIR}/peer0org2.log
}

regen_and_deploy_changes() {
    cd ./caliper
    node genconfigs.js ${FILE_NAME_NO_EXT}
    cd ..

    # clean previous contract results from caliper-vm
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP} 'rm -f ~/caliper-vm/outputs/*'
    ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP} 'rm -f ~/caliper/log/*'

    # copy changed and regenerated artifacts
    scp -i ${SSH_KEY_PATH} ./../../contracts/${FILE_NAME} ${USER_NAME}@${CALIPER_IP}:~/caliper-vm/contracts/${FILE_NAME}
    scp -i ${SSH_KEY_PATH} ./../workloads/${CONTRACT_BASE_NAME}.js ${USER_NAME}@${CALIPER_IP}:~/caliper-vm/workloads/${CONTRACT_BASE_NAME}.js
    scp -i ${SSH_KEY_PATH} ./caliper/network-config.yaml ${USER_NAME}@${CALIPER_IP}:~/caliper-vm/network-config.yaml
    scp -i ${SSH_KEY_PATH} ./caliper/test-config.yaml ${USER_NAME}@${CALIPER_IP}:~/caliper-vm/test-config.yaml

    scp -i ${SSH_KEY_PATH} ./prometheus/prometheus.yaml ${USER_NAME}@${PROMETHEUS_IP}:~/prometheus/prometheus.yaml
}

CONTRACTS_DIR="./../../contracts"
INPUT_FILES="${CONTRACTS_DIR}/*.sol"
OUTPUT_BASE_DIR="./../../eda"

# create dir for results
CAMPAIGN_DATE=$(date +%F_%H-%M)
OUTPUT_DIR=${OUTPUT_BASE_DIR}/dist_${CAMPAIGN_DATE}
mkdir ${OUTPUT_DIR}
mkdir ${OUTPUT_DIR}/logs

# clean up just in case
stop_fabric_nodes
stop_monitoring
clean_artifacts

# deploy the constant artifacts only once

###############################
# Prepare directory structure #
###############################

mkdir ./remote
mkdir ./remote/orderer
mkdir ./remote/peer0org1
mkdir ./remote/peer0org2
mkdir ./remote/caliper-vm
mkdir ./remote/caliper-vm/contracts
mkdir ./remote/caliper-vm/workloads
mkdir ./remote/caliper-vm/outputs

#######################################################
# Assemble Caliper artifacts into ./remote/caliper-vm #
#######################################################

cp -r ./fabric/crypto-config/ ./remote/caliper-vm/crypto-config
cp ./fabric/mychannel.tx ./remote/caliper-vm/mychannel.tx
cp ./caliper/loadgen.js ./remote/caliper-vm/loadgen.js
cp -r ./caliper/loadgen_node_modules ./remote/caliper-vm/node_modules

####################################################
# Assemble Orderer artifacts into ./remote/orderer #
####################################################

cp -r ./fabric/crypto-config/ ./remote/orderer/crypto-config
cp ./fabric/orgs.genesis.block ./remote/orderer/orgs.genesis.block
cp ./fabric/docker-compose-tls-orderer.yaml ./remote/orderer/docker-compose.yaml

#########################################################
# Assemble Peer0.Org1 artifacts into ./remote/peer0Org1 #
#########################################################

cp -r ./fabric/crypto-config/ ./remote/peer0org1/crypto-config
cp ./fabric/docker-compose-tls-peer0org1.yaml ./remote/peer0org1/docker-compose.yaml

#########################################################
# Assemble Peer0.Org2 artifacts into ./remote/peer0Org2 #
#########################################################

cp -r ./fabric/crypto-config/ ./remote/peer0org2/crypto-config
cp ./fabric/docker-compose-tls-peer0org2.yaml ./remote/peer0org2/docker-compose.yaml

##########################
# Pack VM node artifacts #
##########################

tar -zcf ./remote/caliper-vm.tar.gz --directory=./remote caliper-vm
tar -zcf ./remote/orderer.tar.gz --directory=./remote orderer
tar -zcf ./remote/peer0org1.tar.gz --directory=./remote peer0org1
tar -zcf ./remote/peer0org2.tar.gz --directory=./remote peer0org2
tar -zcf ./remote/prometheus.tar.gz prometheus

####################
# Deploy artifacts #
####################

scp -i ${SSH_KEY_PATH} ./remote/caliper-vm.tar.gz ${USER_NAME}@${CALIPER_IP}:~/caliper-vm.tar.gz
scp -i ${SSH_KEY_PATH} ./remote/orderer.tar.gz ${USER_NAME}@${ORDERER_IP}:~/orderer.tar.gz
scp -i ${SSH_KEY_PATH} ./remote/peer0org1.tar.gz ${USER_NAME}@${PEER0ORG1_IP}:~/peer0org1.tar.gz
scp -i ${SSH_KEY_PATH} ./remote/peer0org2.tar.gz ${USER_NAME}@${PEER0ORG2_IP}:~/peer0org2.tar.gz
scp -r -i ${SSH_KEY_PATH} ./remote/prometheus.tar.gz ${USER_NAME}@${PROMETHEUS_IP}:~/prometheus.tar.gz

######################################
# Extract and delete remote archives #
######################################

ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP} 'tar -xzf ~/caliper-vm.tar.gz && rm ~/caliper-vm.tar.gz'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} 'tar -xzf ~/orderer.tar.gz && rm ~/orderer.tar.gz'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} 'tar -xzf ~/peer0org1.tar.gz && rm ~/peer0org1.tar.gz'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} 'tar -xzf ~/peer0org2.tar.gz && rm ~/peer0org2.tar.gz'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} 'tar -xzf ~/prometheus.tar.gz && rm ~/prometheus.tar.gz'

# only start influxdb and grafana
start_influxdb

for FILE_PATH in ${INPUT_FILES}; do
    FILE_NAME=$(basename -- "$FILE_PATH") # e.g., BecToken-0-0.sol
    FILE_NAME_NO_EXT=${FILE_NAME%.*} # e.g., BecToken-0-0
    CONTRACT_BASE_NAME=${FILE_NAME%-*-*} # e.g., BecToken

    LOG_DIR=${OUTPUT_DIR}/logs/${FILE_NAME_NO_EXT}
    mkdir ${LOG_DIR}

    regen_and_deploy_changes
    start_prometheus

    RUN_COUNTER=0

    while [[  RUN_COUNTER -lt 10 ]]; do
        sleep 5s
        start_orderer
        sleep 5s
        start_p0o1
        start_p0o2
        sleep 5s

        ###################
        # Execute Caliper #
        ###################

        # the node path must be exported manually, since it's not installed globally, and .bashrc isn't run for remote sessions
        ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP} 'export PATH=$HOME/.nvm/versions/node/v8.15.0/bin:$PATH;cd caliper;npm run bench -- -c ../caliper-vm/test-config.yaml -n ../caliper-vm/network-config.yaml'

        #################################################
        # Retrieve remote results and CC container logs #
        #################################################

        # prepare empty CSV for TX logs
        LOG_FILE=${FILE_NAME_NO_EXT}.cc.csv
        > ${LOG_FILE}

        # TX data
        scp -r -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP}:~/caliper-vm/outputs ${OUTPUT_DIR}/
        # Caliper logs
        scp -r -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP}:~/caliper/log/* ${LOG_DIR}/

        get_fabric_docker_logs
        get_cc_log ${PEER0ORG1_IP} "1"
        get_cc_log ${PEER0ORG2_IP} "2"
        stop_fabric_nodes

        if [[ -s ./${LOG_FILE} ]]
        then
            mv ./${LOG_FILE} ${OUTPUT_DIR}/outputs/${LOG_FILE}
            mv ./"${LOG_FILE}_raw_org1.log" ${LOG_DIR}/"${LOG_FILE}_raw_org1.log"
            mv ./"${LOG_FILE}_raw_org2.log" ${LOG_DIR}/"${LOG_FILE}_raw_org2.log"
            let RUN_COUNTER=RUN_COUNTER+100
        else
            echo "Trying again ${FILE_NAME_NO_EXT}" >> ${OUTPUT_DIR}/repeated.txt
            sleep 30s
            rm -f ./${LOG_FILE}
            rm -f ./"${LOG_FILE}_raw_org1.log"
            rm -f ./"${LOG_FILE}_raw_org2.log"
            let RUN_COUNTER=RUN_COUNTER+1
        fi
    done

    stop_prometheus
done

##############################
# Final assembly and cleanup #
##############################

merge_results
backup_influxdb
stop_monitoring
compress_results
clean_artifacts