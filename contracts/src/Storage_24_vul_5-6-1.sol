// SPDX-License-Identifier: MIT

pragma solidity >=0.8.2 <0.9.0;

contract Storage {
    uint256 internal number;

    /**
     * @dev Store value in variable
     *  @param num value to store
     */
    function store(uint256  num) public    {
        number = num;
    }


    /**
     * @dev Return value 
     *  @return value of 'number'
     */
    function retrieve() public view returns ( uint256  )    {
    }


}
