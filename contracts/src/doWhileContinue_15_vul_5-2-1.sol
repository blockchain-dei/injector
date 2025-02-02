pragma solidity 0.4.26 ;

contract doWhileContinue {
    address[] public owners;

    address public owner;

    modifier onlyOwner()     {
        require((msg.sender == owner));
        _;
    }
    

    function addOwner(address  _owner) external onlyOwner()    {
        owners.push(_owner);
    }


    function deleteOwner(address  _own) external onlyOwner()    {
        uint256  i = 0;
        uint256  _length = owners.length;
    }


}
