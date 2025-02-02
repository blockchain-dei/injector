'use strict';

const fs = require('fs');
const path = require('path');
const ethabi = require('ethereumjs-abi');
const rewire = require('rewire');
const { Mutex } = require('await-semaphore');
const util = require('../caliper/src/comm/util.js');
const RateInterface = require('../caliper/src/comm/rate-control/rateInterface.js');

const workloadDir = path.join(__dirname, 'workloads');
const outputDir = path.join(__dirname, 'outputs');

module.exports.info  = 'Generates predefined workloads for the Solidity contracts';

let mutex = new Mutex();

// used during the load generation
let blockchain;
let context;
let contract;
let contractAddress;
let writeStream;
let txIndexOfRound;
let clientIndex;

let rwSetDecoderFunction = rewire('../caliper/node_modules/fabric-client/lib/BlockDecoder.js').__get__('decodeProposalResponsePayload');

// the workload definition
let workload = [];

module.exports.init = async (bc, ctx, args) => {
    if (!args.hasOwnProperty('contract')) {
        throw new Error('Missing contract argument');
    }

    if (!ctx.hasOwnProperty('evmUserAddresses') || !ctx.evmUserAddresses.hasOwnProperty('mychannel')) {
        throw new Error(`Missing user context information: ${JSON.stringify(ctx)}`);
    }

    if (!ctx.hasOwnProperty('networkInfo')) {
        throw new Error(`Missing network context information: ${JSON.stringify(ctx)}`);
    }

    if (!ctx.hasOwnProperty('evmContractDescriptors')) {
        throw new Error(`Missing contract description information: ${JSON.stringify(ctx)}`);
    }

    contract = args.contract;
    blockchain = bc;
    context = ctx;
    txIndexOfRound = -1;

    let clients = Array.from(ctx.networkInfo.getClients());
    let addresses = [];
    for (let i = 0; i < clients.length; ++i) {
        addresses[i] = ctx.evmUserAddresses.mychannel[clients[i]];
    }

    let contractBaseName = contract.split('-')[0];
    let workloadFile = fs.readdirSync(workloadDir).find(f => f === `${contractBaseName}.js`);

    if (!workloadFile) {
        throw new Error(`Couldn't find workload file ${contractBaseName}.js`);
    }

    let workloadModule = require(path.join(workloadDir, workloadFile));
    workload = workloadModule.buildWorkload(clients, addresses, ctx.evmContractDescriptors);
    contractAddress = ctx.evmContractDescriptors[contract].address;

    writeStream = fs.createWriteStream(path.join(outputDir, `${contract}.csv`));
};

module.exports.run = async () => {
    let release = await mutex.acquire();

    let idx = ++txIndexOfRound;
    let currentTx = workload[idx];

    let args = {
        chaincodeFunction: currentTx.function,
        chaincodeArguments: currentTx.args,
        invokerIdentity: currentTx.invoker,
        weiValue: currentTx.weiValue,
        nonce: idx
    };

    let txResults;
    if (currentTx.type === 't') {
        txResults = await blockchain.invokeSmartContract(context, contract, '', args, 10);
    } else {
        txResults = await blockchain.bcObj.querySmartContract(context, contract, '', args, 10);
    }

    release();
    let result = txResults[0];

    let id = result.GetID();
    writeStream.write(`${id};status;${result.GetStatus()}\n`);
    writeStream.write(`${id};time_create;${result.GetTimeCreate()}\n`);
    writeStream.write(`${id};time_final;${result.GetTimeFinal()}\n`);
    writeStream.write(`${id};contract_name;${contract}\n`);
    writeStream.write(`${id};function_name;${currentTx.function}\n`);
    writeStream.write(`${id};tx_index;${idx}\n`);
    writeStream.write(`${id};load_generator_idx;${clientIndex}\n`);
    if (currentTx.args) {
        for (let i = 0; i < currentTx.args.length; ++i) {
            writeStream.write(`${id};input_${i};${currentTx.args[i]}\n`);
        }
    }

    let writeOutput = (decode) => {
        if (result.IsCommitted()) {
            let res;
            if (decode) {
                let funcRet = context.evmContractDescriptors[contract].methodSignatures[currentTx.function].returnTypes;
                res = ethabi.rawDecode(funcRet, result.GetResult());
            } else {
                res = result.GetResult();
            }

            writeStream.write(`${id};return_value;${res}\n`);
        }
    };
    let writeEntries = (decode) => {
        for (let entry of result.GetCustomData().entries()) {
            if (entry[0].includes('result')) {
                let res;
                if (decode) {
                    let funcRet = context.evmContractDescriptors[contract].methodSignatures[currentTx.function].returnTypes;
                    res = ethabi.rawDecode(funcRet, entry[1]);
                } else {
                    res = entry[1];
                }
                writeStream.write(`${id};${entry[0]};${res}\n`);
            } else if (entry[0] === 'rwset_payload') {
                let decoded = rwSetDecoderFunction(entry[1]);
                let reads = [];
                let writes = [];

                for (let rw of decoded.extension.results.ns_rwset) {
                    let ns = rw.namespace;

                    for (let read of rw.rwset.reads) {
                        let key = ns + read.key;
                        let version = read.version ? `${read.version.block_num}.${read.version.tx_num}` : 'null';
                        reads.push(`${key}@${version}`);
                    }

                    for (let write of rw.rwset.writes) {
                        // this will ignore EVM Contract Account updates, that contain the surely different bytecodes
                        if (write.key === contractAddress) {
                            continue;
                        }

                        let key = ns + write.key;
                        let value = write.is_delete ? 'null' : Buffer.from(write.value).toString('hex');
                        writes.push(`${key}@${value}`);
                    }
                }

                writeStream.write(`${id};reads;${reads.sort().join('|')}\n`);
                writeStream.write(`${id};writes;${writes.sort().join('|')}\n`);
            } else {
                // keep only the first line (errors usually has more lines)
                writeStream.write(`${id};${entry[0]};${entry[1].toString().split('\n')[0]}\n`);
            }
        }
    };

    let decode = !currentTx.function.startsWith('#');

    writeOutput(decode);
    writeEntries(decode);

    return txResults;
};

module.exports.end = async () => {
    await util.sleep(2000); // wait for flushing every tx data
    writeStream.end();
};

class SequentialRateController extends RateInterface {
    constructor(opts) { super(opts); }

    async init(msg) { }

    async applyRateControl(start, idx, recentResults, resultStats) {
        let release = await mutex.acquire();
        release();
    }

    async end() { }
}

function createRateController(opts, clientIdx, roundIdx) {
    clientIndex = clientIdx;
    return new SequentialRateController(opts);
}

module.exports.createRateController = createRateController;