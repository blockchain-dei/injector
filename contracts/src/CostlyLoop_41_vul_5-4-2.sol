pragma solidity 0.6.2 ;

contract CostlyLoop {
    uint256[] public element;

    uint256 public constant addNum = 1;

    address public owner;

    constructor() public    {
        owner = msg.sender;
    }
    
    modifier onlyOwner()     {
        require((msg.sender == owner));
        _;
    }
    

    function appendDate(uint256  _ele) public onlyOwner()    {
        assert((msg.sender == owner));
        element.push(_ele);
    }


    function addOne() public onlyOwner()    {
        uint256  _length = element.length;
        for (uint8  i = 0; (i < _length); i++) element[i] += 1;
    }


}
