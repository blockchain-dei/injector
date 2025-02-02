#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Missing 1st argument: IP exporter script path"
    exit 1
fi

source "$1"

TEMPLATE_DIR=./templates
FABRIC_ARTIFACTS_DIR=./fabric
PROMETHEUS_ARTIFACTS_DIR=./prometheus
CALIPER_ARTIFACTS_DIR=./caliper

############
# Clean up #
############

rm -f ${CALIPER_ARTIFACTS_DIR}/genconfigs.js

rm -f ${FABRIC_ARTIFACTS_DIR}/configtx.yaml
rm -f ${FABRIC_ARTIFACTS_DIR}/crypto-config.yaml
rm -f ${FABRIC_ARTIFACTS_DIR}/docker-compose-tls-peer0org1.yaml
rm -f ${FABRIC_ARTIFACTS_DIR}/docker-compose-tls-peer0org2.yaml
rm -f ${PROMETHEUS_ARTIFACTS_DIR}/prometheus.yaml

#######################
# Insert IP addresses #
#######################

# peer0.org1 docker
cp ${TEMPLATE_DIR}/docker-compose-tls-peer0org1.yaml.template ${FABRIC_ARTIFACTS_DIR}/docker-compose-tls-peer0org1.yaml
sed -i -e "s/<<<PEER0ORG1_IP>>>/${PEER0ORG1_IP}/g" ${FABRIC_ARTIFACTS_DIR}/docker-compose-tls-peer0org1.yaml

# peer0.org2 docker
cp ${TEMPLATE_DIR}/docker-compose-tls-peer0org2.yaml.template ${FABRIC_ARTIFACTS_DIR}/docker-compose-tls-peer0org2.yaml
sed -i -e "s/<<<PEER0ORG2_IP>>>/${PEER0ORG2_IP}/g" ${FABRIC_ARTIFACTS_DIR}/docker-compose-tls-peer0org2.yaml

# config-tx yaml
cp ${TEMPLATE_DIR}/configtx.yaml.template ${FABRIC_ARTIFACTS_DIR}/configtx.yaml
sed -i -e "s/<<<PEER0ORG1_IP>>>/${PEER0ORG1_IP}/g" ${FABRIC_ARTIFACTS_DIR}/configtx.yaml
sed -i -e "s/<<<PEER0ORG2_IP>>>/${PEER0ORG2_IP}/g" ${FABRIC_ARTIFACTS_DIR}/configtx.yaml
sed -i -e "s/<<<ORDERER_IP>>>/${ORDERER_IP}/g" ${FABRIC_ARTIFACTS_DIR}/configtx.yaml

# crypto-config yaml
cp ${TEMPLATE_DIR}/crypto-config.yaml.template ${FABRIC_ARTIFACTS_DIR}/crypto-config.yaml
sed -i -e "s/<<<PEER0ORG1_IP>>>/${PEER0ORG1_IP}/g" ${FABRIC_ARTIFACTS_DIR}/crypto-config.yaml
sed -i -e "s/<<<PEER0ORG2_IP>>>/${PEER0ORG2_IP}/g" ${FABRIC_ARTIFACTS_DIR}/crypto-config.yaml
sed -i -e "s/<<<ORDERER_IP>>>/${ORDERER_IP}/g" ${FABRIC_ARTIFACTS_DIR}/crypto-config.yaml

# genconfig for Caliper config generation
cp ${TEMPLATE_DIR}/genconfigs.js.template ${CALIPER_ARTIFACTS_DIR}/genconfigs.js
sed -i -e "s/<<<PEER0ORG1_IP>>>/${PEER0ORG1_IP}/g" ${CALIPER_ARTIFACTS_DIR}/genconfigs.js
sed -i -e "s/<<<PEER0ORG2_IP>>>/${PEER0ORG2_IP}/g" ${CALIPER_ARTIFACTS_DIR}/genconfigs.js
sed -i -e "s/<<<ORDERER_IP>>>/${ORDERER_IP}/g" ${CALIPER_ARTIFACTS_DIR}/genconfigs.js

###############################
# regenerate crypto materials #
###############################

if [[ $2 = "nogen" ]]; then
    echo "Skipping crypto and channel tx generation"
else
    rm -rf ${FABRIC_ARTIFACTS_DIR}/crypto-config
    rm -f ${FABRIC_ARTIFACTS_DIR}/mychannel.tx
    rm -f ${FABRIC_ARTIFACTS_DIR}/orgs.genesis.block

    cd ${FABRIC_ARTIFACTS_DIR}
    ./generate.sh
fi