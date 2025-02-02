## Flat API

### Queries

|     Function      | Parameters | Return value | Constraints | Description                                              |
|:-----------------:|:----------:|:------------:|:------------|:---------------------------------------------------------|
|      primary      |     -      |   address    |             | Returns the address of the primary.                      |
|       state       |     -      |    State     |             | Returns the current state of the escrow.                 |
|    beneficiary    |     -      |   address    |             | Returns the address of the beneficiary.                  |
|    depositsOf     |  address   |   uint256    |             | Returns the current deposit amount for the given address |
| withdrawalAllowed |  address   |   boolean    |             | Determines whether withdrawal is allowed.                |

### TXs

|      Function       | Parameters | Return value | Constraints              | Description                                          |
|:-------------------:|:----------:|:------------:|:-------------------------|:-----------------------------------------------------|
|       deposit       |  address   |      -       | primary, payable, Active | Deposits the attached wei to the given address.      |
|   transferPrimary   |  address   |      -       | primary                  | Changes the primary.                                 |
|      withdraw       |  address   |      -       | primary                  | Withdraws whole amount of the given address' deposit |
|        close        |     -      |      -       | primary, Active          | Closes the escrow.                                   |
|    enableRefunds    |     -      |      -       | primary, Active          | Enables refunding.                                   |
| beneficiaryWithdraw |     -      |      -       | Closed                   | Transfers the contract balance to the beneficiary    |

## Actors

|    Actor    |                                 Description                                 |
|:-----------:|:---------------------------------------------------------------------------:|
|   Primary   |                  The creator of the contract (initially).                   |
| Beneficiary |          Can receive the contract balance upon closing the escrow.          |
|   General   | Can query the contract details and initiate a withdraw for the beneficiary. |

## States 

|               | Active |   Refunding   | Closed |
|:-------------:|:------:|:-------------:|:------:|
|  **Active**   |   *    | enableRefunds | close  |
| **Refunding** |   -    |       *       |   -    |
|  **Closed**   |   -    |       -       |   *    |

## Workload

The following calls can be made in each state.

|      Function       |   Sender    |     Parameters      |
|:-------------------:|:-----------:|:-------------------:|
|       primary       |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |
|        state        |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |
|     beneficiary     |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |
|     depositsOf      |   primary   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     | beneficiary |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     |   general   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|  withdrawalAllowed  |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |
|       deposit       |   primary   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     | beneficiary |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     |   general   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|   transferPrimary   |   primary   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     | beneficiary |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     |   general   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|      withdraw       |   primary   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     | beneficiary |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
|                     |   general   |   primary address   |
|                     |             | beneficiary address |
|                     |             |   general address   |
|                     |             |    zero address     |
| beneficiaryWithdraw |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |
|        close        |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |
|    enableRefunds    |   primary   |          -          |
|                     | beneficiary |          -          |
|                     |   general   |          -          |