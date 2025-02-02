// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0 ;

contract MultiConstructor {
    address public owner;

    uint public initialValue;

    string public name;

    constructor(uint _initialValue) {
        owner = msg.sender; // L'indirizzo che distribuisce il contratto diventa il proprietario
        initialValue = _initialValue;
        name = "Default Name"; // Valore predefinito
    }

    function initializeWithName(string memory _name, uint _initialValue) public {
        require(bytes(name).length == 0, "Already initialized"); // Impedisce doppia inizializzazione
        require(msg.sender == owner, "Only owner can initialize");
        
        name = _name;
        initialValue = _initialValue;
    }
}
