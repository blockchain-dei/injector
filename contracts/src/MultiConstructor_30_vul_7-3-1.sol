// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0 ;

contract MultiConstructor {
    address public owner;

    uint public initialValue;

    string public name;

    constructor(uint  _initialValue) public    {
        owner = msg.sender;
        initialValue = _initialValue;
        name = "Default Name";
    }
    
    function initializeWithName(string memory _name, uint32  _initialValue) public    {
        require((bytes(name).length == 0), "Already initialized");
        require((msg.sender == owner), "Only owner can initialize");
        name = _name;
        initialValue = _initialValue;
    }


}
