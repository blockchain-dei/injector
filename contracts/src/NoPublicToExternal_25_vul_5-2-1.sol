pragma solidity 0.5.16 ;

contract NoPublicToExternal {
    uint256 public contractBirthday;

    address public owner;

    function refund() external    {
        require((msg.sender == owner));
        if ((now > (contractBirthday + 1 weeks))) selfdestruct(msg.sender);
    }


    function refund2(address  owner2) external    {
        require(((msg.sender == owner) || (msg.sender == owner2)));
        if ((now > (contractBirthday + 1 weeks))) selfdestruct(msg.sender);
    }


    function refund3(address  owner2) external    {
        require(((msg.sender == owner) && (msg.sender == owner2)));
        if ((now > (contractBirthday + 1 weeks))) selfdestruct(msg.sender);
    }


    function refund4(uint256  setAutorized) external    {
        require(((setAutorized == 1) || (setAutorized == 2)));
        if ((now > (contractBirthday + 1 weeks))) selfdestruct(msg.sender);
    }


    function refund5(uint256  setAutorized) external    {
        require(((setAutorized == 1) && (setAutorized == 2)));
        if ((now > (contractBirthday + 1 weeks))) selfdestruct(msg.sender);
    }


}
