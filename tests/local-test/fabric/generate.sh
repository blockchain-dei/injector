#!/bin/bash

# if the ./bin directory doesn't exist, run ./install-binaries.sh first!
if [[ ! -d './bin' ]]; then
  ./install-binaries.sh 1.4.0
fi

rm -rf ./crypto-config/
rm -f ./mychannel.tx
rm -f ./orgs.genesis.block

# The below assumes you have the relevant code available to generate the cryto-material
./bin/cryptogen generate --config=./crypto-config.yaml
./bin/configtxgen -profile OrgsOrdererGenesis -outputBlock orgs.genesis.block -channelID syschannel
./bin/configtxgen -profile OrgsChannel -outputCreateChannelTx mychannel.tx -channelID mychannel

# Rename the key files we use to be key.pem instead of a uuid
for KEY in $(find crypto-config -type f -name "*_sk"); do
    KEY_DIR=$(dirname ${KEY})
    mv ${KEY} ${KEY_DIR}/key.pem
done