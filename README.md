Commands:

# to know what current version of Solidity compiler is:
solc --version 

# to set what version of Solidity compiler should be used:
solc-select use 0.8.21

# to get a Compact AST structure of a smart contract
solc --ast-compact-json Abs5.sol > Abs5-ast.json

# inject a vulnerability into a smart contract:
python3 vul-1-3-1.py 3-1a_Fixed.sol