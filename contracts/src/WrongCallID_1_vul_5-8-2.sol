pragma solidity ^0.5.0 ;

contract WrongCallID {
    address public owner;

    constructor() public    {
        owner = msg.sender;
    }
    
    function isOwner() public view returns ( bool  )    {
        if ((msg.sender == owner))
            {
                return true;
            }
        return false;
    }


}
