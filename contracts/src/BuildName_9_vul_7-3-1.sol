pragma solidity >=0.4.26 ;

contract BuildName {
    address internal owner;

    bytes32 internal bytesnum;

    bytes32 internal hashnum;

    function Old(uint32  num) public    {
        owner = msg.sender;
        bytesnum = sha3(num);
        hashnum = block.blockhash(num);
    }


    function getOwner() public returns ( address  )    {
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
