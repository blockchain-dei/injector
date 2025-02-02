pragma solidity 0.5.16 ;

contract ProxySub {
    address internal client;

    constructor(address  _client) public    {
        client = _client;
    }
    
    // Forward call to "setOwner(address)" that is implemented by client
    // after doing basic validation on the address argument.
    function forward(bytes calldata _payload, address  owner) external returns ( bool  )    {
        int  a = 1;
        int  b = 2;
        if ((a == b))
            {
                assert((owner != address(0)));
                a = (a + 1);
            }
        return true;
    }


}
