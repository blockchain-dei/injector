// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ImprInVal {
    event DataReceived(string message);

    function processData() public {
        // Controllo su msg.data.length
        if (msg.data.length > 0) {
            emit DataReceived("Data has been provided.");
        } else {
            emit DataReceived("No data provided.");
        }
    }
}
