# Running measurements in BME Cloud

> __Note:__ the following workflow is specific to BME Cloud VMs!

## Table of contents
* [VM template](#vm-template)
* [VM instances](#vm-instances)
  * [Setup SSH](#setup-ssh)
  * [Open ports](#open-ports)
* [VM-specific setup](#vm-specific-setup)
  * [Caliper VM](#caliper-vm)
  * [Orchestrator VM](#orchestrator-vm)
* [Run measurements](#run-measurements)
  * [Setting the host names](#setting-the-host-names)
  * [Instantiating template files](#instantiating-template-files)
  * [Running the measurement](#running-the-measurement)
* [Exploring the results](#exploring-the-results)
  * [ID-related](#id-related)
  * [Fault injection-related](#fault-injection-related)
  * [Chaincode-related](#chaincode-related)
  * [EVM-related](#evm-related)
  * [Endorsement-related](#endorsement-related)
  * [Commit-related](#commit-related)
  * [Transaction-related](#transaction-related)
  * [Formal verification-related](#formal-verification-related)
* [Benchmark workflow](#benchmark-workflow)


## VM template

`Ubuntu 18.04 Fabric v1` is a template for Fabric, Caliper, Monitoring and Orchestrator nodes. It contains the following tools:
* Git 2.17.1
* Go 1.11.5
* Docker 18.06.2-ce
* Docker Compose 1.23.1
* Node.js 8.15.0 LTS
* Conda 4.7.11 & conda-execute 0.9.0
* InfluxDB CLI 1.7.7

The template is configured with the following resources:
* 4 vCPU
* 8GB RAM
* 40GB storage

## VM instances

Create the following VMs from the `Ubuntu 18.04 Fabric v1` template:
* Caliper
* Orchestrator
* Orderer
* Peer0Org1
* Peer0Org2
* Prometheus

The instances require the following additional setup (unfortunately, these are not inherited from the template):
1. Setup key-based SSH access (through password-based SSH)
2. Open ports (through Dashboard __AND__ firewall)

> The instances use the `cloud` user.

Consider the IPv4 SSH port of the current VM exported, to make the following commands copy-paste friendly. At first, the `ssh` commands require passwords, which you can find on the VM dashboards.

```bash
export VM_PORT="<IPv4 SSH port>"
```

### Setup SSH

A single SSH key pair was generated to access all VM instances, named `fabric-bme` and `fabric-bme.pub`.

The benchmark script requires key-based SSH access for the VMs. Use `ssh-copy-id` to add the `fabric-bme.pub` key to `authorized_keys` on each VM.

Execute the following for every VM instance from a machine that has `fabric-bme.pub`:

```bash
ssh-copy-id -i ~/.ssh/fabric-bme.pub cloud@vm.smallville.cloud.bme.hu -p ${VM_PORT}
```

__The orchestrator VM will also need the private key to communicate with the other VMs:__

```bash
scp -i ~/.ssh/fabric-bme -P ${VM_PORT} ~/.ssh/fabric-bme cloud@vm.smallville.cloud.bme.hu:~/.ssh/fabric-bme
```

Verify whether you can successfully login with the key (and set the ports in the next section):
```bash
ssh -i ~/.ssh/fabric-bme cloud@vm.smallville.cloud.bme.hu -p ${VM_PORT}
```

### Open ports

For every VM above, add the following ports for forwarding on the VM dashboard's networking tab:
* 2375: Docker daemon
* 3000: Grafana
* 7050: Fabric Orderer
* 7051: Fabric Peer
* 8086: InfluxDB HTTP
* 8088: InfluxDB Management
* 9000: Fabric metrics
* 9090: Prometheus
* 9100: node_exporter metrics

Also, open the same ports inside the VMs:

```bash
sudo ufw allow 2375
sudo ufw allow 3000
sudo ufw allow 7050
sudo ufw allow 7051
sudo ufw allow 8086
sudo ufw allow 8088
sudo ufw allow 9000
sudo ufw allow 9090
sudo ufw allow 9100
```

## VM-specific setup

Some VM instance requires additional setup, like cloning the required GitHub repositories.

### Caliper VM

> __Note:__ the following steps must be executed on the Caliper VM!

To bootstrap Caliper, run the following commands:

```bash
git clone https://github.com/aklenik/caliper.git
cd caliper

git checkout fabric-evm
npm install
npm run fabric-evm-deps
```

### Orchestrator VM

> __Note:__ the following steps must be executed on the Orchestrator VM!

To bootstrap the Orchestrator node, clone this repository:

```bash
git clone https://github.com/FTSRG/smartcontract-faultinjection.git
```

> __Note:__ if you have 2FA enabled on GitHub, then the password is your GitHub Personal Access Token.

## Run measurements

> __Note:__ the following steps must be executed on the Orchestrator VM!

__The VM setups need to be done only once. After that, the steps from here should be followed every time a measurement needs to be executed.__ 

Switch to the directory for distributed tests:
```bash
cd ~/smartcontract-faultinjection/tests/distributed-test
```

### Setting the host names
The pre-requisite of every measurement is a script that exports the necessary IP addresses and SSH key paths. The script that exports the default private network IPs is `ip.sh`:

```bash
#!/bin/bash

export CALIPER_IP=10.9.0.104
export ORDERER_IP=10.9.0.89
export PEER0ORG1_IP=10.9.0.101
export PEER0ORG2_IP=10.9.0.135
export PROMETHEUS_IP=10.9.0.104

export USER_NAME=cloud
export SSH_KEY_PATH="~/.ssh/fabric-bme -oStrictHostKeyChecking=no"
```

> __IMPORTANT!!__ Do not push public IP addresses into the repository! The `tests/distributed-test/.gitignore` file lists every sensitive file that should be ignored, use it!

### Instantiating template files

Most of the configuration files depend on the IP addresses. So when the IP addresses change (or the first time the repository is cloned), the dependent files must be generated:

```bash
./instantiate-templates.sh ip.sh
```

The script requires the path of the IP exporting script file as its argument.

### Running the measurement

To start the measurement, run the `run.sh` script, passing the path of the IP exporting script as its argument:

```bash
./run.sh ip.sh
```

The script performs the experiment for every contract in the `contracts` root directory of the repository. The results will be automatically saved and merged in the `eda` root directory of the repository, into a timestamped directory. The `MERGED.csv` file in that directory contains every TX data.

## Exploring the results

The `MERGED.csv` files contain data about each transaction during the complete measurement. The records of the table correspond to data gathered about a given transaction.

### ID-related

| Variable | Type | Description |
|:---|:---:|:---|
| `ID_tx_id` | string  | The unique ID/hash of the TX  |
| `ID_contract_sol_classname` | enum | The family name of the contract |
| `ID_contract_family_base` | enum | The family base for the contract (i.e., the basile name) |
| `ID_protection_type` | enum | The protection level of the contract: baseline, stripped or protected |
| `ID_contract_filename` | enum | The contract variant file name |
| `ID_faulty_contract` | boolean | Indicates whether the contract is injected or not |
| `ID_odc_fault_name_specific` | enum | The abbreviation of the ODC fault name |
| `ID_mutation_instance_for_type` | integer | The mutant variant of the contract |
| `ID_fabric_request_type` | enum | Either `transaction` or `query` |
| `ID_function_name` | string | The name of the called Solidity contract |
| `ID_contract_paramdcall_idx` | integer | The index of the TX in the workload |
| `ID_mutation_variant_id` | string | Concatenation of the ODC fault ID and variant ID |
| `ID_mutation_variant_name` | string | Concatenation of the ODC fault name and variant ID |

### Fault injection-related

| Variable | Type | Description |
|:---|:---:|:---|
| `FI_bc_specific_fault` | boolean | Indicates whether the fault is specific to blockchain platforms |
| `FI_odc_type_name` | enum | The name of the ODC type |
| `FI_odc_nature_name` | enum | The name of the ODC nature |

### Chaincode-related

| Variable | Type | Description |
|:---|:---:|:---|
| `CHAINCODE_p<X>o<Y>_runtime_ns` | integer | The chaincode invoke runtime in nanoseconds on peer `<X>` of org `<Y>` |
| `CHAINCODE_p<X>o<Y>_start_epoch_ns` | integer | The chaincode invoke start time epoch in nanoseconds on peer `<X>` of org `<Y>` |
| `CHAINCODE_p<X>o<Y>_end_epoch_ns` | integer | The chaincode invoke end time epoch in nanoseconds on peer `<X>` of org `<Y>` |
| `CHAINCODE_refdelta_p<X>o<Y>_runtime_ns` | integer | The chaincode invoke runtime difference in nanoseconds on peer `<X>` of org `<Y>` compared to the reference TX. Formula: `TX(current, runtime) - TX(reference, runtime)` |

### EVM-related

| Variable | Type | Description |
|:---|:---:|:---|
| `EVM_p<X>o<Y>_runtime_ns` | integer | The EVM invoke runtime in nanoseconds on peer `<X>` of org `<Y>` |
| `EVM_p<X>o<Y>_start_epoch_ns` | integer | The EVM invoke start time epoch in nanoseconds on peer `<X>` of org `<Y>` |
| `EVM_p<X>o<Y>_end_epoch_ns` | integer | The EVM invoke end time epoch in nanoseconds on peer `<X>` of org `<Y>` |
| `EVM_refdelta_p<X>o<Y>_runtime_ns` | integer | The EVM invoke runtime difference in nanoseconds on peer `<X>` of org `<Y>` compared to the reference TX. Formula: `TX(current, runtime) - TX(reference, runtime)` |

### Endorsement-related

| Variable | Type | Description |
|:---|:---:|:---|
| `ENDORSE_any_error` | boolean | Indicates whether there were any proposal response errors from the peers |
| `ENDORSE_p<X>o<Y>_callresult` | string | The return value of the Solidity function call for peer `<X>` of org `<Y>`. |
| `ENDORSE_p<X>o<Y>_error` | string | The returned proposal response error (if any) for peer `<X>` of org `<Y>`. |

### Commit-related

| Variable | Type | Description |
|:---|:---:|:---|
| `COMMIT_anypeer_failure` | enum | The final status of the TX. Either `failed` or `success`.
| `COMMIT_p<X>o<Y>_error` | string |  The returned commit error (if any) for peer `<X>` of org `<Y>`. |

### Transaction-related

| Variable | Type | Description |
|:---|:---:|:---|
| `TX_create_epoch_ms` | integer | The epoch when the TX was created in Caliper, in milliseconds |
| `TX_create_relative_ms` | integer | The normalized time of when the TX was created in Caliper, in milliseconds. Relative to the first TX create time in the workload.
| `TX_total_time_ms` | integer | The end-to-end execution time of the TX in milliseconds |
| `TX_endorses_rcv_duration_ms` | integer | The time it took to receive the endorsements from the peers, in milliseconds, counted from TX creation time |
| `TX_ordervalidate_rcv_duration_ms` | integer | The time it took to order and validate/commit the TX on all peers, in milliseconds, counted from when the endorsements were received |
| `TX_refdelta_total_time_ms` | integer | The end-to-end TX time difference in milliseconds, compared to the reference TX. Formula: `TX(current,total_time) - TX(reference,total_time)` |
| `TX_refdelta_endorses_rcv_duration_ms` | integer | The endorsing time difference in milliseconds, compared to the reference TX. Formula: `TX(current,endorses_rcv_duration) - TX(reference,endorses_rcv_duration)` |
| `TX_refdelta_ordervalidate_rcv_duration_ms` | integer | The order and validate/commit time difference in milliseconds, compared to the reference TX. Formula: `TX(current,ordervalidate_duration) - TX(reference,ordervalidate_duration)` |
| `TX_read_set_empty` | boolean | Indicates whether the read set is empty or not. Always `true` for queries |
| `TX_write_set_empty` | boolean | Indicates whether the write set is empty or not. Always `true` for queries |
| `TX_client_view_consistent` | boolean | Indicates whether the client observes the same behavior for this and the reference TX. Formula: `same_function_return_value && same_tx_status` |
| `TX_hidden_side_effect` | boolean | Indicates whether there were any hidden side effects of the transaction (i.e., not observable for the client). Formula: `client_view_consistent & !same_write_set` |
| `TX_execution_fullmatch` | boolean | Indicates whether the TX result completely matches the reference TX. Formula: `same_function_return_value & same_read_set & same_write_set & same_tx_status` |
| `TX_ref_success` | boolean | Indicates whether the reference TX was successfully committed or not |
| `TX_commit_match_endorse_error_refined` | enum | Compares the `ENDORSE_any_error` values of the TX with its reference TX and classifies the difference in a True/False Positive/Negative manner: `TP`, `FP`, `TN`, `FN` |
| `TX_commit_match_endorse_error` | 0/1 | Simplified version of the `TX_commit_match_endorse_error_refined` value. `0` for True Positive/Negative matches, `1` for False Positive/Negative matches |
| `TX_commit_match_return_value` | boolean | Indicates whether the function return value of the TX matches its reference TX |
| `TX_commit_match_read_set` | boolean | Indicates whether the read set of the TX matches its reference TX |
| `TX_commit_match_read_set_refined` | enum | Compares the read set of the TX with its reference TX. `0_MATCH_EMPTY` for matching empty read sets, `0_MATCH_ALL` for matching non-empty read sets and `MISMATCH` otherwise |
| `TX_commit_match_write_set` | boolean | Indicates whether the write set of the TX matches its reference TX |
| `TX_commit_match_write_set_refined` | enum | Compares the write set of the TX with its reference TX. `0_MATCH_EMPTY` for matching empty write sets, `0_MATCH_ALL` for matching non-empty write sets and `MISMATCH` otherwise |
| `TX_ref_writeset_empty` | boolean | Indicates whether the reference TX has any empty write set or not |
| `TX_commit_match_status` | boolean | Indicates whether the commit status of the TX matches its reference TX |
| `TX_commit_match_status_refined` | enum | Compares the commit status of the TX with its reference. Either `0_MATCH_SUCCESS`, `0_MATCH_FAILURE`, `UNEXPECTED_FAILURE` or `UNEXPECTED_SUCCESS` |
| `TX_fabric_timeout` | boolean | Indicates whether a Fabric-level timeout occurred |
| `TX_evm_timeout` | boolean | Indicates whether an EVM-level timeout (i.e., out of gas) occurred |
| `TX_timeout` | boolean | Indicates whether a Fabric-level or EVM-level timeout occurred |

### Formal verification-related

| Variable | Type | Description |
|:---|:---:|:---|
| `FORMAL_result` | enum | Indicates whether the formal verification found the contract correct or not. Either `TRUE`, `FALSE` or `UNKNOWN` |
| `FORMAL_result_classification` | enum | The True/False Positive/Negative classification of the formal verification result. `TIMEOUT` for verifications that timed out |
| `FORMAL_result_correct` | boolean | Indicates whether the formal verification decided correctly |
| `FORMAL_assert_failures` | number | The number of `assert` failures |
| `FORMAL_loopinv_failures` | number | The number of `loopinv` failures |
| `FORMAL_overflow_failures` | number | The number of `overflow` failures |
| `FORMAL_contrinv_failures` | number | The number of `contrinv` failures |
| `FORMAL_postcond_failures` | number | The number of `postcond` failures |
| `FORMAL_modification_failures` | number | The number of `modification` failures |
| `FORMAL_reentrancy_failures` | number | The number of `reentrancy` failures |


## Aggregated results

The TX-level result are aggregated according to the `ID_contract_filename` variable. Contract-level variables have the same definition as above. 

### Transaction-related

| Variable | Type | Description |
|:---|:---:|:---|
| `TX_fabric_timeout` | boolean | Indicates whether **any** Fabric-level timeout occurred during the TX sequence |
| `TX_evm_timeout` | boolean | Indicates whether **any** EVM-level timeout (i.e., out of gas) occurred during the TX sequence |
| `TX_timeout` | boolean | Indicates whether **any** Fabric-level or EVM-level timeout occurred during the TX sequence |
| `TX_hidden_side_effect` | boolean | Indicates whether **any** TX with hidden side-effect occurred during the TX sequence |
| `TX_data_integrity_error` | boolean | Indicates whether **any** successful TX with mismatching write-set occurred during the TX sequence |
| `TX_reliability_error` | boolean | Indicates whether **any** TX with inconsistent client view occurred during the TX sequence |
| `TX_accessibility_error` | boolean | Indicates whether **any** TX with unexpected failure occurred during the TX sequence |
| `TX_execution_fullmatch` | boolean | Indicates whether **all** TX in the sequence matched the execution of its reference TX |

## Pushing the results

> __Note:__ the following steps must be executed on the Orchestrator VM!

Once the result is ready, push the repository. It is recommended to compress the resulting CSVs.
To do this, navigate to the `eda` directory and execute the `archive.sh` script passing the timestamped directory name as argument:

```bash
cd ~/smartcontract-faultinjection/eda
./archive.sh dist_[timestamp]
```

The logs and other raw data are already compressed at the end of the benchmark run.
Finally, add, commit and push the changes.

## Benchmark workflow

![](Benchmark%20workflow.png)