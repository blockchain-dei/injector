# Soldity AST

This project contains utilities to
- read Solitidy ASTs in JSON format produced by the [Solidity compiler](https://github.com/ethereum/solidity),
- manipulate the ASTs (e.g., fault injection),
- serialize the AST to source code.

The project has some common modules (e.g., serialization) and different manipulation modules that are listed below.
The project requires Python 3 and the [Solidity compiler (solc) extended with formal verification (solc-verify)](https://github.com/SRI-CSL/solidity/) to be available on the path.
See its [readme](https://github.com/SRI-CSL/solidity/blob/boogie/SOLC-VERIFY-README.md) for installation instructions.

## Manipulation modules

Use `./inject-all.sh Contract.sol` to inject all types of faults into a contract.
This script calls each manipulator module in the `ast` directory.
As a result files with name `Contract-<fault_id>-<variant>.sol`.
Each fault has an _ID_ and if it can be injected to multiple places, there will be multiple _variants_.

Use `./create-csv.py <dir>` to list the generated files (in a given directory) to a csv file.
Currently, it only works if the file names match the main contract name in the file.
E.g., `MyContract-1-2.sol` should contain a `MyContract` contract.

The manipulator modules (in the directory `ast`) can also be called independently.
Use the `-h` option to read more about their behaivor and parameters.
These scripts usually take a single input file and inject the fault into all possible locations, generating possibly multiple output files.

Use the `/** @notice noinject */` documentation tag over an element (e.g., function) if you do not want to inject any faults into that element (and its children).

### Example

Consider the example contract (`examples/Abs.sol`).
It has a single function which calculates the absolute value of the parameter and asserts that the result should be non-negative.

```
pragma solidity ^0.4.24;

contract Abs {
    function abs(int8 x) public pure returns (int8) {
        int8 y = x;
        if (y < 0) y *= -1;
        assert(y >= 0);
        return y;
    }
}
```

Running `./ast/remove-if.py examples/Abs.sol` will generate a new file since there is only one `if` statement that can be removed.

The resulting contract (`examples/Abs-24-1.sol`):
```
pragma solidity^0.4.24;

contract Abs {
    function abs(int8 x) public pure returns (int8) {
        int8 y = x;
        y *= (-1);
        assert((y >= 0));
        return y;
    }
}
```

**Running the verifier**

The verifier developed at SRI International is called [solc-verify](https://github.com/SRI-CSL/solidity/tree/boogie/).

Running it on the original contract proves correctness.

```
$ solc-verify.py examples/Abs.sol --errors-only
No errors found.
```

Running the verifier on the faulty contract reveals the assertion failure.

```
$ solc-verify.py examples/Abs-24-1.sol --errors-only
Source examples/Abs-24-1.sol, line 8, col 9: Assertion might not hold.
Errors were found by the verifier.
```

## Workload generator
Use the `ast/testgen.py` script to generate a workload for a given contract.
The script will inspect the functions of the contract and generate possible transactions.
The values for each parameter in the transaction is based on
- the type of the parameter (e.g. minimal/maximal integers),
- the literals appearing in the function (e.g., comparisons),
- and randomly (e.g., random strings).

For examle `./ast/testgen.py examples/BecToken.sol`.
The generator currently works for integers, addresses, strings and arrays.
There are some parameters in the beginning of the script which can be adjusted.

## Serialization modules (for developers)

The script `ast/serializer.py` contains the following methods.
- `readast` can read an AST in JSON format or in Solidity source (.sol) format.
In the latter case it first calls the compiler to produce a temporary JSON file.
- `writeast` can write an AST in JSON format to Solidity source (.sol).
It can also be used as a standalone script: `./ast/serializer.py input.json output.sol`.

## Common modules (for developers)

The module `ast/common.py` contains some common AST manipulation methods.
Its most important method is the `inject`, which takes two functions `cond` and `act`.
The function `cond` defines a condition on a node which should return true if the fault can be injected to that node.
The function `act` defines the action, i.e., it injects the fault into the node (assuming that `cond` is true).
Furthermore, it takes a path to the input file (`infile`) and a suffix.
It will inject the fault defined by `act` to every node where `cond` holds.
For each injection, a new file is written, named `<infile>-<suffix>-<n>`, where `n` is the counter.
Maniplation modules call this method with their own conditions and actions.
