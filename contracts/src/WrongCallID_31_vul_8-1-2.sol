// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0 ;

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


    function setOwner() public    {
        owner = msg.sender;
    }


}
