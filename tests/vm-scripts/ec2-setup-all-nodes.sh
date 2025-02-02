#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Missing 1st argument: IP exporter script path"
    exit 1
fi

source "$1"

scp -i ${SSH_KEY_PATH} ./ec2-caliper-node.sh ${USER_NAME}@${CALIPER_IP}:~/ec2-caliper-node.sh
scp -i ${SSH_KEY_PATH} ./ec2-fabric-node.sh ${USER_NAME}@${ORDERER_IP}:~/ec2-fabric-node.sh
scp -i ${SSH_KEY_PATH} ./ec2-fabric-node.sh ${USER_NAME}@${PEER0ORG1_IP}:~/ec2-fabric-node.sh
scp -i ${SSH_KEY_PATH} ./ec2-fabric-node.sh ${USER_NAME}@${PEER0ORG2_IP}:~/ec2-fabric-node.sh
scp -r -i ${SSH_KEY_PATH} ./ec2-prometheus-node.sh ${USER_NAME}@${PROMETHEUS_IP}:~/ec2-prometheus-node.sh

ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${CALIPER_IP} './ec2-caliper-node.sh'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${ORDERER_IP} './ec2-fabric-node.sh'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG1_IP} './ec2-fabric-node.sh'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PEER0ORG2_IP} './ec2-fabric-node.sh'
ssh -i ${SSH_KEY_PATH} ${USER_NAME}@${PROMETHEUS_IP} './ec2-prometheus-node.sh'