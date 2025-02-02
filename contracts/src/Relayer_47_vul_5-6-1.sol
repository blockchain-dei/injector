pragma solidity 0.5.16 ;

contract Relayer {
    address public owner;

    mapping(bytes => bool) internal executed;

    function relay(bytes memory _data) public returns ( bool  )    {
        require((executed[_data] == false), "Duplicate call");
        executed[_data] = true;
        owner = msg.sender;
        owner.call(abi.encodePacked("execute(bytes)", _data));
    }


}

contract Executor {
    function execute(bytes memory _data, uint  _gasLimit) public    {
        require((gasleft() >= _gasLimit));
        _data = "";
    }


}
