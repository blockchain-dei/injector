## Flat API

### Queries

| Function | Parameters | Return value | Constraints   | Description                                  |
|:--------:|:----------:|:------------:|:--------------|:---------------------------------------------|
|   get    |  address   |     int      | record is set | Returns the record data at the given address |

### TXs

|  Function   | Parameters | Return value | Constraints       | Description                                        |
|:-----------:|:----------:|:------------:|:------------------|:---------------------------------------------------|
| changeOwner |  address   |      -       | only owner        | Transfers the ownership to the new address.        |
|     set     |    int     |      -       | storage not set   | Sets the corresponding storage to the given value. |
|   update    |    int     |      -       | storage set       | Updates the storage value to the given value.      |
|    clear    |  address   |      -       | only owner or own | Clear the storage value at the given address.      |

## Actors

|  Actor  |                                 Description                                 |
|:-------:|:---------------------------------------------------------------------------:|
|  Owner  |                     The owner/deployer of the contract                      |
| General | No distinguished actors, but the contract creator gets every token at first |

## States 

The contract is not state-based.

## Workload

### sender / Actor
* owner
* other addresses (set and not set storage)

### get
* address
  * zero address
  * owner address
  * unset address
  * set address

### set
* storage state
  * set
  * not set
* value
  * non-zero
  * zero
  
### update
* storage state
  * set
  * not set
* value
  * negative
  * zero
  * positive
  
### clear
* storage state
  * set
  * not set
* address
  * zero address
  * owner address
  * other address (own or not)
  
### changeOwner
* address
  * owner address
  * other address (set or not set)
  * zero address (no more owner changes are possible)