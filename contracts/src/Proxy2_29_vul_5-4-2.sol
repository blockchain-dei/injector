pragma solidity 0.5.16 ;

contract Proxy2 {
    address internal client;

    constructor(address  _client) public    {
        client = _client;
    }
    
    // Forward call to "setOwner(address)" that is implemented by client
    // after doing basic validation on the address argument.
    function forward(bytes memory _payload, address  owner) public returns ( bool  )    {
        assert((owner != address(0)));
        owner = msg.sender;
        return true;
    }


}
