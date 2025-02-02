pragma solidity 0.5.16;

contract Relayer {
    address public owner;
    mapping (bytes => bool) executed;
    function relay(bytes memory _data)  public returns (bool)  {
        // replay protection; do not call the same transaction twice
        require(executed[_data] == false, "Duplicate call");
        executed[_data] = true;
        owner = msg.sender; 
        owner.call(abi.encodePacked("execute(bytes)", _data));
        //address payable _addrExecute;
       //(bool success, bytes memory data) =_addrExecute.call(abi.encodePacked("execute(bytes)", _data));
       // data = "";
        return true;
    }
}


contract Executor {
    function execute(bytes memory  _data, uint _gasLimit)  public{
        require(gasleft() >= _gasLimit);
        _data=""; 
        // continue code
    }
}