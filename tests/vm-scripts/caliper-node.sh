#!/bin/bash

echo "##########"
echo "# GOLANG #"
echo "##########"

GO_VERSION="1.11.5"

mkdir -p ${HOME}/gopath

cd ${HOME}
wget https://storage.googleapis.com/golang/go${GO_VERSION}.linux-amd64.tar.gz
tar -xzf go${GO_VERSION}.linux-amd64.tar.gz
rm -f go${GO_VERSION}.linux-amd64.tar.gz

echo "GOROOT=$HOME/go" >> ~/.profile
echo "GOPATH=$HOME/gopath" >> ~/.profile
echo 'PATH=$PATH:$GOROOT/bin:$GOPATH/bin' >> ~/.profile
echo 'export GOPATH' >> ~/.profile
echo 'export GOROOT' >> ~/.profile
echo 'export PATH' >> ~/.profile

source $HOME/.profile

echo "##########"
echo "# DOCKER #"
echo "##########"

DOCKER_VERSION="18.06.2" # or try version 18.09.9

# set up repo
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update

# install
sudo apt-get install -y docker-ce=${DOCKER_VERSION}~ce~3-0~ubuntu # if using v18.09.9 change this to ...docker-ce=${DOCKER_VERSION}~3-0~ubuntu-bionic

# set up group to avoid constant sudo-ing
sudo usermod -aG docker ${USER}
sudo service docker restart

# set up docker daemon listening ports
sudo sed -i "/ExecStart=/c\ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock --api-cors-header='*' --default-ulimit=nofile=8192:16384 --default-ulimit=nproc=8192:16384" /lib/systemd/system/docker.service

sudo systemctl daemon-reload
sudo systemctl restart docker.service

echo "##################"
echo "# DOCKER COMPOSE #"
echo "##################"

DOCKER_COMPOSE_VERSION="1.23.1"
# get the latest release version number from: https://github.com/docker/compose/releases/latest
sudo curl -L https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

echo "#############"
echo "# TIME SYNC #"
echo "#############"

sudo timedatectl set-ntp no
sudo apt-get install -y chrony
sudo timedatectl set-local-rtc 1 --adjust-system-clock

echo "#######"
echo "# NVM #"
echo "#######"

NVM_VERSION="0.34.0"

# get the lates version from https://github.com/creationix/nvm
curl -o- https://raw.githubusercontent.com/creationix/nvm/v${NVM_VERSION}/install.sh | bash

echo "###########"
echo "# NODE JS #"
echo "###########"

NODE_VERSION="8.15.0"

# making nvm available inside the script
. $HOME/.nvm/nvm.sh

nvm install ${NODE_VERSION}
nvm use ${NODE_VERSION}
nvm alias default ${NODE_VERSION}

# install gulp globally
npm install -g gulp

echo "##############"
echo "# PYTHON 2.7 #"
echo "##############"

cd ${HOME}
sudo apt-get -y install python2.7

# grpc install needs the python command
sudo ln -s /usr/bin/python2.7 /usr/bin/python

echo "#################"
echo "# NODE EXPORTER #"
echo "#################"

cd ${HOME}
curl -LO https://github.com/prometheus/node_exporter/releases/download/v0.17.0/node_exporter-0.17.0.linux-amd64.tar.gz
tar -xvf node_exporter-0.17.0.linux-amd64.tar.gz
sudo mv node_exporter-0.17.0.linux-amd64/node_exporter /usr/local/bin/

rm -rf node_exporter-0.17.0.linux-amd64.tar.gz
rm -rf node_exporter-0.17.0.linux-amd64/

sudo useradd -rs /bin/false node_exporter

echo "[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter --no-collector.arp --no-collector.bcache --no-collector.bonding --no-collector.conntrack --no-collector.edac --no-collector.entropy --no-collector.filefd --no-collector.hwmon --no-collector.infiniband --no-collector.ipvs --no-collector.loadavg --no-collector.mdadm --no-collector.netclass --no-collector.netstat --no-collector.nfs --no-collector.nfsd --no-collector.sockstat --no-collector.stat --no-collector.textfile --no-collector.time --no-collector.timex --no-collector.uname --no-collector.vmstat --no-collector.xfs --no-collector.zfs
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target" | sudo tee -a /lib/systemd/system/node_exporter.service

sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter

echo "###########"
echo "# CALIPER #"
echo "###########"

# needed to compile fabric packages
sudo apt-get install -y make g++

cd ${HOME}
git clone https://github.com/aklenik/caliper.git
cd caliper
git checkout fabric-evm
npm install
npm run fabric-evm-deps
