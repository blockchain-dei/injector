'use strict';

const zeroAddress = '0x0000000000000000000000000000000000000000';

// addresses:
// [0]: creator address, Initiating Counterparty, Owner, initial Counterparty
// [1]: Device
// [2]: Supply Chain Owner
// [3]: Supply Chain Observer
// [0, 2-5]: Can be Counterparty (except for device)

function buildWorkload(c, a, evmContracts) {
    // fix roles
    const creatorIdentity = c[0];
    const deviceIdentity = c[1];
    const supplyChainOwnerIdentity = c[2];
    const supplyChainObserverIdentity = c[3];
    const nextCounterpartyIdentity = c[4];
    const nextNextCounterpartyIdentity = c[5];

    const creatorAddress = a[0];
    const deviceAddress = a[1];
    const supplyChainOwnerAddress = a[2];
    const supplyChainObserverAddress = a[3];
    const nextCounterpartyAddress = a[4];
    const nextNextCounterpartyAddress = a[5];

    return [
        /////////////////////////////////////////////////////////////////////////////////
	    // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // created state, ingest telemetry
        // wrong roles
        {type: 't', invoker: creatorIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: supplyChainOwnerIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: supplyChainObserverIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: nextCounterpartyIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // correct role and values (out-of-order and duplicate timestamps timestamps)
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['40', '20', '10']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['40', '20', '5']},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // transfer to InTransit state (wrong invoker, address doesn't matter for now)
        {type: 't', invoker: deviceIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: supplyChainOwnerIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: supplyChainObserverIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: nextCounterpartyIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        // transfer to InTransit state (correct invoker, wrong target address)
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // InTransit state
        // transfer to InTransit state (correct invoker, zero target address)
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ zeroAddress ]},
        // transfer to InTransit state (correct invoker, self target address)
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ creatorAddress ]},
        // real transfer
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ nextCounterpartyAddress ]},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // ingest telemetry
        // wrong roles
        {type: 't', invoker: creatorIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: supplyChainOwnerIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: supplyChainObserverIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: nextCounterpartyIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        // correct role and values (out-of-order and duplicate timestamps timestamps)
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['50', '25', '40']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['50', '25', '40']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['40', '20', '50']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['40', '20', '30']},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // transfer responsibility (wrong invoker, address doesn't matter for now)
        {type: 't', invoker: deviceIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: supplyChainOwnerIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: supplyChainObserverIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: nextCounterpartyIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        // transfer responsibility (correct invoker, wrong target address)
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // transfer (correct invoker, zero target address)
        {type: 't', invoker: nextCounterpartyIdentity, function: 'TransferResponsibility', args: [ zeroAddress ]},
        // transfer (zero address caused phantom counterparty)
        {type: 't', invoker: nextCounterpartyIdentity, function: 'TransferResponsibility', args: [ nextNextCounterpartyAddress ]},
        // real transfer (owner is like an admin role)
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ nextNextCounterpartyAddress ]},

        // move to out of compliance state (with out-of-range humidity)
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['5', '25', '100']},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        ////////////////////////////////////////////
        // every TX will fail after this
        {type: 't', invoker: creatorIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: supplyChainOwnerIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: supplyChainObserverIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},
        {type: 't', invoker: nextCounterpartyIdentity, function: 'IngestTelemetry', args: ['50', '25', '0']},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // correct role and values (out-of-order and duplicate timestamps timestamps)
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['50', '25', '40']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['50', '25', '40']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['40', '20', '50']},
        {type: 't', invoker: deviceIdentity, function: 'IngestTelemetry', args: ['40', '20', '30']},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // transfer responsibility (wrong invoker, address doesn't matter for now)
        {type: 't', invoker: deviceIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: supplyChainOwnerIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: supplyChainObserverIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        {type: 't', invoker: nextCounterpartyIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},
        // transfer responsibility (correct invoker, wrong target address)
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ deviceAddress ]},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'},
        /////////////////////////////////////////////////////////////////////////////////

        // transfer (correct invoker, zero target address)
        {type: 't', invoker: nextCounterpartyIdentity, function: 'TransferResponsibility', args: [ zeroAddress ]},
        {type: 't', invoker: creatorIdentity, function: 'TransferResponsibility', args: [ nextNextCounterpartyAddress ]},

        /////////////////////////////////////////////////////////////////////////////////
        // QUERY SET
        {type: 'q', invoker: creatorIdentity, function: 'State'},
        {type: 'q', invoker: creatorIdentity, function: 'Owner'},
        {type: 'q', invoker: creatorIdentity, function: 'InitiatingCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Counterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'PreviousCounterparty'},
        {type: 'q', invoker: creatorIdentity, function: 'Device'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainOwner'},
        {type: 'q', invoker: creatorIdentity, function: 'SupplyChainObserver'},
        {type: 'q', invoker: creatorIdentity, function: 'MinHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxHumidity'},
        {type: 'q', invoker: creatorIdentity, function: 'MinTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'MaxTemperature'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorType'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceSensorReading'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceStatus'},
        {type: 'q', invoker: creatorIdentity, function: 'ComplianceDetail'},
        {type: 'q', invoker: creatorIdentity, function: 'LastSensorUpdateTimestamp'}
        /////////////////////////////////////////////////////////////////////////////////
	];
}

// address device, address supplyChainOwner, address supplyChainObserver,
// int minHumidity, int maxHumidity, int minTemperature, int maxTemperature
module.exports.ctrInit = ['$USER_2', '$USER_3', '$USER_4', '10', '90', '-50', '50'];
module.exports.buildWorkload = buildWorkload;
module.exports.workloadLength = 252;
