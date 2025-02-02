# Tx Data Merging

## Pre-requisites
The `./tx-data-merge.py` script manages all dependencies through the `conda-execute` tool, so individual packages does not need to be installed, just a `conda` distribution and `conda-execute`. The pre-requisite installation with [Miniconda](https://docs.conda.io/en/latest/miniconda.html) looks like the following:

```bash
wget https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda.sh
bash miniconda.sh -b
echo 'PATH=$PATH:$HOME/miniconda3/bin' >> ~/.profile
source $HOME/.profile
conda install conda-execute --channel=conda-forge
```

## Usage

To generate the merged CSVs, run the `./merge.sh` script. The script assembles the `local-test-MERGED.csv` and `distributed-test-csv` files if the corresponding test outputs are available.

If you plan to open the resulting CSVs in Mondrian, also run the `./mondrian-fix.sh` script with the CSV file path as argument: 

`./mondrian-fix.sh ./local-test-MERGED.csv`

`./mondrian-fix.sh ./distributed-test-MERGED.csv`