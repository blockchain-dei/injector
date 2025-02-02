pragma solidity ^0.5.0 ;

contract ImprInVal {
    event DataReceived(string  message);

    function processData() public    {
        if ((msg.data.length > 0))
            {
                emit DataReceived("Data has been provided.");
            }
        else 
            {
                emit DataReceived("No data provided.");
            }
    }


}
