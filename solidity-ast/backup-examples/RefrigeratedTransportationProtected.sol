pragma solidity >=0.5.0;

/// @notice invariant ComplianceStatus || State == StateType.OutOfCompliance
/// @notice invariant !ComplianceStatus || State != StateType.OutOfCompliance
contract RefrigeratedTransportationProtected
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
    /// @notice postcondition x == ComplianceDetail
    function IngestTelemetry(int humidity, int temperature, int timestamp) public returns (int x)
    {
        // Separately check for states and sender
        // to avoid not checking for state when the sender is the device
        // because of the logical OR
        if ( State == StateType.Completed )
        {
            revert();
        }

        if ( State == StateType.OutOfCompliance )
        {
            revert();
        }

        if (Device != msg.sender)
        {
            revert();
        }

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

        assert(State != StateType.OutOfCompliance ||
            (State == StateType.OutOfCompliance &&
                (humidity > MaxHumidity || humidity < MinHumidity || temperature > MaxTemperature || temperature < MinTemperature)));
        assert(!(humidity > MaxHumidity || humidity < MinHumidity || temperature > MaxTemperature || temperature < MinTemperature) || State == StateType.OutOfCompliance);
        assert(!(humidity > MaxHumidity || humidity < MinHumidity) || ComplianceDetail == 1);
        assert(!(!(humidity > MaxHumidity || humidity < MinHumidity) && (temperature > MaxTemperature || temperature < MinTemperature)) || ComplianceDetail == 2);
        return ComplianceDetail;
    }

    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.Completed)
    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.OutOfCompliance)
    /// @notice postcondition msg.sender == __verifier_old_address(InitiatingCounterparty) || msg.sender == __verifier_old_address(Counterparty)
    /// @notice postcondition newCounterparty != __verifier_old_address(Device)
    /// @notice postcondition PreviousCounterparty == __verifier_old_address(Counterparty)
    /// @notice postcondition Counterparty == newCounterparty
    function TransferResponsibility(address newCounterparty) public returns (address)
    {
        // keep the state checking, message sender, and device checks separate
        // to not get cloberred by the order of evaluation for logical OR
        if ( State == StateType.Completed )
        {
            revert();
        }

        if ( State == StateType.OutOfCompliance )
        {
            revert();
        }

        if ( InitiatingCounterparty != msg.sender && Counterparty != msg.sender )
        {
            revert();
        }

        if ( newCounterparty == Device )
        {
            revert();
        }

        if (State == StateType.Created)
        {
            State = StateType.InTransit;
        }

        PreviousCounterparty = Counterparty;
        Counterparty = newCounterparty;

        assert(Counterparty == newCounterparty);
        return Counterparty;
    }

    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.Completed)
    /// @notice postcondition __verifier_old_uint(uint(State)) != uint(StateType.OutOfCompliance)
    /// @notice postcondition Owner == msg.sender || SupplyChainOwner == msg.sender
    /// @notice postcondition State == StateType.Completed
    /// @notice postcondition PreviousCounterparty == __verifier_old_address(Counterparty)
    /// @notice postcondition Counterparty == address(0x0000000000000000000000000000000000000000)
    function Complete() public returns (StateType)
    {
        // keep the state checking, message sender, and device checks separate
        // to not get cloberred by the order of evaluation for logical OR
        if ( State == StateType.Completed )
        {
            revert();
        }

        if ( State == StateType.OutOfCompliance )
        {
            revert();
        }

        if (Owner != msg.sender && SupplyChainOwner != msg.sender)
        {
            revert();
        }

        State = StateType.Completed;
        PreviousCounterparty = Counterparty;
        Counterparty = 0x0000000000000000000000000000000000000000;

        assert(State == StateType.Completed);
        assert(Counterparty == address(0x0000000000000000000000000000000000000000));

        return State;
    }
}