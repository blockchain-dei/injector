## Flat API

### Queries

|         Function          | Parameters | Return value | Constraints | Description                                                           |
|:-------------------------:|:----------:|:------------:|:------------|:----------------------------------------------------------------------|
|           State           |     -      |    uint8     | -           | Returns the current state of the supply chain.                        |
|           Owner           |     -      |   address    | -           | Returns the address of the owner of the contract.                     |
|  InitiatingCounterparty   |     -      |   address    | -           | Returns the address of the initiating counterparty.                   |
|       Counterparty        |     -      |   address    | -           | Returns the address of the current counterparty.                      |
|   PreviousCounterparty    |     -      |   address    | -           | Returns the address of the previous counter-party.                    |
|          Device           |     -      |   address    | -           | Returns the address of the device.                                    |
|     SupplyChainOwner      |     -      |   address    | -           | Returns the address of the supply chain owner.                        |
|    SupplyChainObserver    |     -      |   address    | -           | Returns the address of the supply chain observer.                     |
|        MinHumidity        |     -      |     int      | -           | Returns the satisfactory minimum humidity.                            |
|        MaxHumidity        |     -      |     int      | -           | Returns the satisfactory maximum humidity.                            |
|      MinTemperature       |     -      |     int      | -           | Returns the satisfactory minimum temperature.                         |
|      MaxTemperature       |     -      |     int      | -           | Returns the satisfactory maximum temperature.                         |
|   ComplianceSensorType    |     -      |    uint8     | -           | Returns the type of the sensor that violated the compliance criteria. |
|  ComplianceSensorReading  |     -      |     int      | -           | Returns the sensor reading that violated the compliance criteria.     |
|     ComplianceStatus      |     -      |     bool     | -           | Returns whether the compliance criteria is satisfied or not.          |
|     ComplianceDetail      |     -      |    string    | -           | Returns the reason for violating the compliance criteria.             |
| LastSensorUpdateTimestamp |     -      |     int      | -           | Returns the timestamp of the last reading.                            |

### TXs

|        Function        |  Parameters   | Return value | Constraints                                                                                  | Description                                                            |
|:----------------------:|:-------------:|:------------:|:---------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------|
|    IngestTelemetry     | int, int, int |      -       | sender is Device and state is Created or InTransit                                       | Stores the timestamp of the telemetries and check compliance criteria. |
| TransferResponsibility |    address    |      -       | sender is (Initiating)Counterparty and state is Created or InTransit                         | Sets the new responsible counterparty.                                 |
|        Complete        |       -       |      -       | sender is InitiatingCounterparty/Owner or SupplyChainOwner and state is Created or InTransit | Deems the supply chain complete.                                       |

## Actors

|          Actor          |                                                                          Description                                                                          |
|:-----------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| Initiating Counterparty | The first participant in the supply chain. Also the owner of the contract. Can deem a supply complete. The first counterparty in the chain. Deploy-time role. |
|          Owner          |                                                    Same as the initiating counterparty. Deploy-time role.                                                     |
|      Counterparty       |                                    A party to whom responsibility for a product has been assigned. For example, a shipper.                                    |
|  Previous Counterparty  |                                                            The previous counterparty in the chain                                                             |
|         Device          |                 A device used to monitor the temperature and humidity of the environment the good(s) are being shipped in. Deploy-time role.                  |
|   Supply Chain Owner    |             The organization that owns the product being transported. For example, a manufacturer. Can deem a supply complete. Deploy-time role.              |
|  Supply Chain Observer  |          The individual or organization monitoring the supply chain. For example, a government agency. Deploy-time role. No associated constraints.           |

## States 

1. **Created**: indicates that the contract has initiated and tracking is in progress.
2. **InTransit**: indicates that a counterparty currently is in possession and responsible for goods being transported.
3. **Completed**: indicates that the product has reached its intended destination.
4. **OutOfCompliance**: indicates that the agreed upon terms for temperature and humidity conditions were not met.

|                     |   **Created**   |             **InTransit**              | **Completed** | **OutOfCompliance** |
|:-------------------:|:---------------:|:--------------------------------------:|:-------------:|:-------------------:|
|     **Created**     | IngestTelemetry |         TransferResponsibility         |   Complete    |   IngestTelemetry   |
|    **InTransit**    |        -        | IngestTelemetry/TransferResponsibility |   Complete    |   IngestTelemetry   |
|    **Completed**    |        -        |                   -                    |       -       |          -          |
| **OutOfCompliance** |        -        |                   -                    |       -       |          -          |

## Workload

### Query set
* for every state variable
* after every state transition (or after some/every self-loop transition)

### State-based TXs
* In the Created and InTransit states
    * Perform each TX with a bad role
    * Perform self-loop TXs with multiple inputs (without triggering state change)
      * IngestTelemetry:
        * Correct values, with different timestamps
          * Smaller than previous
          * Same as previous
          * Larger than previous
        * Violating values, only at the end of the workload, because that state transition to **OutOfCompliance** will be the last
      * TransferResponsibility
        * with invalid roles
        * with valid roles (reentrant)
* In the OutOfCompliance state
    * Every TX with every role with every parameter category (all will be rejected)