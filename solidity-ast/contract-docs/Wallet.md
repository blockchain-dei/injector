## Flat API

### Queries

| Function  | Parameters | Return value | Constraints      | Description                                      |
|:---------:|:----------:|:------------:|:-----------------|:-------------------------------------------------|
| balanceOf |  address   |     uint     | non-zero address | Returns the deposit amount at the given address. |

### TXs

| Function | Parameters | Return value | Constraints | Description                                        |
|:--------:|:----------:|:------------:|:------------|:---------------------------------------------------|
| deposit  |    wei     |      -       | -           | Deposits the attached amount of wei of the sender. |
| withdraw |     -      |      -       | -           | Withdraws the deposited wei of the sender.         |

## Actors

|  Actor  |       Description       |
|:-------:|:-----------------------:|
| General | No distinguished actors |

## States 

The contract is not state-based.

## Workload

### sender / Actor
* general address

### balanceOf
* address
  * zero address
  * owner address
  * other address

### deposit
* wei value
  * zero
  * value << balance
  * value == balance
  * value > balance
  
### withdraw
* for zero-deposit accounts
* for non-zero-deposit accounts

# Future work
Reentrancy attack (needs infrastructure adjustment)