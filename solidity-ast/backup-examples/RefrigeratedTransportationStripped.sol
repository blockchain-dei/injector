pragma solidity >=0.5.0;

/// @notice invariant ComplianceStatus || State == StateType.OutOfCompliance
/// @notice invariant !ComplianceStatus || State != StateType.OutOfCompliance
contract RefrigeratedTransportationStripped
{
    //Set of States
    enum StateType { Created, InTransit, Completed, OutOfCompliance}
    enum SensorType { None, Humidity, Temperature }

    //List of properties
    StateType public  State;
    address public  Owner;
    address public  InitiatingCounterparty;
    address public  Counterparty;
    address public  PreviousCounterparty;
    address public  Device;
    address public  SupplyChainOwner;
    address public  SupplyChainObserver;
    int public  MinHumidity;
    int public  MaxHumidity;
    int public  MinTemperature;
    int public  MaxTemperature;
    SensorType public  ComplianceSensorType;
    int public  ComplianceSensorReading;
    bool public  ComplianceStatus;
    int public  ComplianceDetail;
    int public  LastSensorUpdateTimestamp;

    /// @notice postcondition ComplianceStatus == true
    /// @notice postcondition ComplianceSensorReading == -1
    /// @notice postcondition InitiatingCounterparty == msg.sender
    /// @notice postcondition Owner == InitiatingCounterparty
    /// @notice postcondition Counterparty == InitiatingCounterparty
    /// @notice postcondition Device == device
    /// @notice postcondition SupplyChainOwner == supplyChainOwner
    /// @notice postcondition SupplyChainObserver == supplyChainObserver
    /// @notice postcondition MinHumidity == minHumidity
    /// @notice postcondition MaxHumidity == maxHumidity
    /// @notice postcondition MinTemperature == minTemperature
    /// @notice postcondition MaxTemperature == maxTemperature
    /// @notice postcondition State == StateType.Created
    /// @notice noinject
    constructor(address device, address supplyChainOwner, address supplyChainObserver, int minHumidity, int maxHumidity, int minTemperature, int maxTemperature) public
    {
        ComplianceStatus = true;
        ComplianceSensorReading = -1;
        InitiatingCounterparty = msg.sender;
        Owner = InitiatingCounterparty;
        Counterparty = InitiatingCounterparty;
        Device = device;
        SupplyChainOwner = supplyChainOwner;
        SupplyChainObserver = supplyChainObserver;
        MinHumidity = minHumidity;
        MaxHumidity = maxHumidity;
        MinTemperature = minTemperature;
        MaxTemperature = maxTemperature;
        State = StateType.Created;
        ComplianceDetail = 0;
    }

    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.Completed)
    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.OutOfCompliance)
    /// @notice postcondition __verifier_old_address(Device) == msg.sender
    /// @notice postcondition LastSensorUpdateTimestamp == timestamp
    /// @notice postcondition State != StateType.OutOfCompliance || (State == StateType.OutOfCompliance && (humidity > MaxHumidity || humidity < MinHumidity || temperature > MaxTemperature || temperature < MinTemperature))
    /// @notice postcondition !(humidity > MaxHumidity || humidity < MinHumidity || temperature > MaxTemperature || temperature < MinTemperature) || State == StateType.OutOfCompliance
    /// @notice postcondition !(humidity > MaxHumidity || humidity < MinHumidity) || ComplianceDetail == 1
    /// @notice postcondition !(!(humidity > MaxHumidity || humidity < MinHumidity) && (temperature > MaxTemperature || temperature < MinTemperature)) || ComplianceDetail == 2
    function IngestTelemetry(int humidity, int temperature, int timestamp) public
    {
        LastSensorUpdateTimestamp = timestamp;

        if (humidity > MaxHumidity || humidity < MinHumidity)
        {
            ComplianceSensorType = SensorType.Humidity;
            ComplianceSensorReading = humidity;
            ComplianceDetail = 1;
            ComplianceStatus = false;
        }
        else if (temperature > MaxTemperature || temperature < MinTemperature)
        {
            ComplianceSensorType = SensorType.Temperature;
            ComplianceSensorReading = temperature;
            ComplianceDetail = 2;
            ComplianceStatus = false;
        }

        if (ComplianceStatus == false)
        {
            State = StateType.OutOfCompliance;
        }
    }

    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.Completed)
    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.OutOfCompliance)
    /// @notice postcondition msg.sender == __verifier_old_address(InitiatingCounterparty) || msg.sender == __verifier_old_address(Counterparty)
    /// @notice postcondition newCounterparty != __verifier_old_address(Device)
    /// @notice postcondition PreviousCounterparty == __verifier_old_address(Counterparty)
    /// @notice postcondition Counterparty == newCounterparty
    function TransferResponsibility(address newCounterparty) public
    {
        if (State == StateType.Created)
        {
            State = StateType.InTransit;
        }

        PreviousCounterparty = Counterparty;
        Counterparty = newCounterparty;
    }

    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.Completed)
    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.OutOfCompliance)
    /// @notice postcondition Owner == msg.sender || SupplyChainOwner == msg.sender
    /// @notice postcondition State == StateType.Completed
    /// @notice postcondition PreviousCounterparty == __verifier_old_address(Counterparty)
    /// @notice postcondition Counterparty == address(0x0000000000000000000000000000000000000000)
    function Complete() public
    {
        State = StateType.Completed;
        PreviousCounterparty = Counterparty;
        Counterparty = 0x0000000000000000000000000000000000000000;
    }
}