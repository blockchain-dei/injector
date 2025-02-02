pragma solidity >=0.4.26 ;

contract deprecated {
    address internal owner;

    bytes32 internal bytesnum;

    bytes32 internal hashnum;

    function Old(uint256  num) public    {
        uint256  unusedVar = 42;
        owner = msg.sender;
        bytesnum = sha3(num);
        var  a = 0;
        hashnum = block.blockhash(num);
    }


    function getOwner() public view returns ( address  )    {
        return owner;
    }


    function callAnother() public    {
        if (owner.callcode(""))
            {
                throw;
            }
        else 
            {
                require((msg.sender == owner));
                suicide(owner);
            }
    }


    function () external    {
        if ((msg.gas > 2300))
            {
                throw;
            }
    }


}
