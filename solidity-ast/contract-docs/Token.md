## Flat API

### Queries

| Function  | Parameters | Return value | Constraints | Description                                    |
|:---------:|:----------:|:------------:|:------------|:-----------------------------------------------|
| balanceOf |  address   |   uint256    |             | Returns the token balance of the given address |

### TXs

|   Function    |     Parameters     | Return value | Constraints                                           | Description                                                     |
|:-------------:|:------------------:|:------------:|:------------------------------------------------------|:----------------------------------------------------------------|
|   transfer    |  address, uint256  |     bool     | non-zero value, sufficient balance                    | Transfers the given amount of token to the specified address.   |
| batchTransfer | address[], uint256 |     bool     | non-zero value, sufficient balance, max 20 recipients | Transfers the given amount of token to the specified addresses. |

## Actors

|    Actor    |                                 Description                                 |
|:-----------:|:---------------------------------------------------------------------------:|
|   General   | No distinguished actors, but the contract creator gets every token at first |

## States 

The contract is not state-based.

## Workload

### sender / Actor
* creator
* other address

### balanceOf
* query with zero address
* query with own address
* query with other addresses

### transfer
* receiver
  * zero address
  * own address
  * other addresses
* value
  * 0
  * 1
  * 0 << value << balance
  * value > balance
  
### batchTransfer
* receivers
  * empty
  * single zero address
  * single own address
  * single other addresses
  * has zero address
  * has own address
  * has zero and own address
* value
  * 0
  * 1
  * 0 << value << balance
  * value > balance