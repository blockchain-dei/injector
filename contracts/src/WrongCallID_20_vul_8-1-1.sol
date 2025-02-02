// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0 ;

contract WrongCallID {
    address public owner;

    constructor() public    {
        owner = msg.sender;
    }
    
    function isOwner() public view returns ( bool  )    {
        if ((tx.origin == owner))
            {
                return true;
            }
        return false;
    }


}
