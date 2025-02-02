# Local tests using Truffle

## Preparation

Install dependencies and create an environment:
```
pip3 install nodeenv
sudo apt install nodeenv -y
nodeenv --requirements=node-requirements.txt .env --prebuilt
```

Activate the environment:
```
source .env/bin/activate
```

## Testing

There is a simple test case in the `abs` directory.
The contract is in file `contracts/Abs.sol` while the test (workload) is defined `test/Abs.js`.
For calls, the return value is simply the return value of the function.
For transactions, the return value is the transaction receipt.

Run tests:
```
cd abs
truffle test
```


## Create an empty project

```
mkdir project_name
truffle init
```
