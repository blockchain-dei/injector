'use strict';

const fs = require('fs');
const path = require('path');
const csv = require('csvtojson');
const yaml = require('js-yaml');

// either a limit for the number of entries to read, or a single contract name
const args = process.argv.slice(2);

if (args.length !== 1) {
    console.log('Expected contract name as first parameter, e.g., RefundEscrow-0-0');
    process.exit(1);
}

// the current contract for which we generate the configurations, e.g., RefundEscrow-0-0
const currentContract = args[0];
const caliperArtifactsDir = path.join(__dirname);
const workloadDir = path.join(__dirname, '..', '..', 'workloads');
const contractsMetadataFile = path.join(__dirname, '..', '..', '..', 'metadata', 'contracts.csv');
const csvDelimiter = ';';

// the round section needs to be parameterized according to the current contract
let testConfig = yaml.safeLoad(fs.readFileSync(path.join(__dirname, 'templates/test-config.yaml')), 'utf8');

// the chaincode section needs to be parameterized according to the current contract
let networkConfig = yaml.safeLoad(fs.readFileSync(path.join(__dirname, 'templates/network-config.yaml')), 'utf8');

(async () => {
    const contracts = await csv({delimiter: csvDelimiter}).fromFile(contractsMetadataFile);
    let contractRow = contracts.filter(c => c.contract_name === currentContract);

    // this shouldn't happen, but just in case
    if (contractRow.length !== 1) {
        console.log(`${contractRow.length} contracts match the name "${currentContract}"`);
        process.exit(2);
    }

    // keep the only element
    contractRow = contractRow[0];

    const workloadFile = fs.readdirSync(workloadDir).find(f => f === `${contractRow.contract_classname}.js`);
    if (!workloadFile) {
        console.log(`Couldn't find workload file ${contractRow.contract_classname}.js`);
        process.exit(2);
    }

    const workloadModule = require(path.join(workloadDir, workloadFile));

    testConfig.test.rounds.push({
        label: contractRow.contract_name,
        txNumber: [ workloadModule.workloadLength ],
        rateControl: [ {type: '../smartcontract-faultinjection/tests/local-test/caliper/loadgen.js', opts: {}}],
        arguments: { contract: contractRow.contract_name },
        callback: '../smartcontract-faultinjection/tests/local-test/caliper/loadgen.js'
    });

    let cc = {
        id: contractRow.contract_name,
        version: 'v0',
        language: 'solidity',
        //path: `../smartcontract-faultinjection/contracts/${contractRow.contract_name}.sol`,
        bytecode: {
            path: `../smartcontract-faultinjection/contracts/bytecode/${contractRow.contract_name}.bin`
        },
        abi: {
            path: `../smartcontract-faultinjection/contracts/abi/${contractRow.contract_name}.json`
        },
        contractName: contractRow.contract_classname,
        deployerIdentity: 'client1.org1.example.com',
    };

    if (workloadModule.ctrInit) {
        cc.init = workloadModule.ctrInit;
    }

    networkConfig.channels.mychannel.chaincodes.push(cc);

    // save the resulting configurations
    fs.writeFileSync(path.join(caliperArtifactsDir, 'test-config.yaml'), yaml.safeDump(testConfig, {lineWidth: 10000}), 'utf-8');
    fs.writeFileSync(path.join(caliperArtifactsDir, 'network-config.yaml'), yaml.safeDump(networkConfig, {lineWidth: 10000}), 'utf-8');
})();
