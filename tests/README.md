# Running end-to-end measurements

## Pre-requisites

Both local and distributed measurements require `Node.js 8.x LTS`, the `conda` framework, the `conda-execute` package and `influxd` to be available on the "Controller machine".

### Node.js

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.34.0/install.sh | bash

# making nvm available inside the script
. $HOME/.nvm/nvm.sh

nvm install 8.15.0
nvm use 8.15.0
nvm alias default 8.15.0
```

### Conda and conda-execute

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda.sh
bash ~/miniconda.sh -b -p ~/miniconda 
rm ~/miniconda.sh

conda install -c conda-forge conda-execute
```

### Influx CLI

```bash
wget -qO- https://repos.influxdata.com/influxdb.key | sudo apt-key add -
source /etc/lsb-release
echo "deb https://repos.influxdata.com/${DISTRIB_ID,,} ${DISTRIB_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
sudo apt-get update && sudo apt-get install influxdb
```

## Distributed measurements

### Setting up remote nodes

This step only needs to be performed one, for uninitialized VMs.

There are 3 types of nodes that participate in a measurement:
1. A node running Caliper
1. Fabric nodes running peers, orderers and optionally CAs
1. A node running Prometheus (with InfluxDB and Grafana)

The `vm-scripts` directory contains automatic install scripts for all these types. Copy (`scp`) the appropriate script to the remote node, and execute it. A session restart might be necessary for some packages.

**NOTE:** The scripts prefixed with `ec2-` additionally configure the AWS Time Sync service. The other scripts simply use the default NTP pool configured for `chrony`.

Check the result of the install by running the following commands where appropriate:
```bash
chrony -v # all VM
go version # all VM
docker -v # all VM
docker-compose -v # all VM

sudo systemctl status node_exporter.service # Fabric and Caliper VMs

nvm --version # Caliper VM
node -v # Caliper VM
npm -v # Caliper VM
python --version # Caliper VM
```

### Setting up the measurement

The artifacts for the distributed measurements are located in the `distributed-test` directory. 

`cd ./distributed-test`

#### Setting the IP addresses
The pre-requisite of every measurement is a script that exports the necessary IP addresses and SSH key paths. The script that exports the default private network IPs is `ip.sh`:

```bash
#!/bin/bash

export CALIPER_IP=10.3.4.49
export ORDERER_IP=10.3.4.9
export PEER0ORG1_IP=10.3.4.90
export PEER0ORG2_IP=10.3.4.69
export PROMETHEUS_IP=10.3.4.49

export USER_NAME=ubuntu
export SSH_KEY_PATH="~/.ssh/coimbra.pem -oStrictHostKeyChecking=no"
```

A similar script can be constructed for AWS EC2 instances, for example. 

**IMPORTANT!!** Do not push public IP addresses into the repository! The `tests/distributed-test/.gitignore` file lists every sensitive file that should be ignored, do not modify it!

#### Instantiating template files

Most of the configuration files depend on the IP addresses. So when the IP addresses change (or the first time the repository is cloned), the dependent files must be generated:

```bash
./instantiate-templates.sh ip.sh
```

The script requires the path of the IP exporting script file as its argument.
#### Running the measurement

To start the measurement, run the `run.sh` script, passing the path of the IP exporting script as its argument:

```bash
./run.sh ip.sh
```

The script performs the experiment for every contract in the `contracts` root directory of the repository. The results will be automatically saved and merged in the `eda` root directory of the repository, into a timestamped directory. 

The `MERGED.csv` file in that directory contains every TX data. The `mondrian-MERGED.csv` has the same content, but with Mondrian compatible formatting.