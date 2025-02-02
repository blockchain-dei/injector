pragma solidity 0.5.16;

// SPDX-License-Identifier: GPL-3.0-or-later
contract Proxy2 {
    /// @dev Address of the client contract managed by proxy i.e., this contract
    address client;

    constructor(address _client) public {
        client = _client;
    }

    /// Forward call to "setOwner(address)" that is implemented by client
    /// after doing basic validation on the address argument.
    function forward(bytes memory  _payload,address  owner)  public returns(bool) {
        require(owner != address(0), "Address of owner cannot be zero.");
        owner = msg.sender;
        //owner.call(abi.encodePacked('execute(bytes)', _data));
        return true;
        // return true;
    }
}