// SPDX-License-Identifier: MIT
pragma solidity ^0.4.0;

contract MyToken {
    string public name = "MyToken";
    string public symbol = "MTK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balances;

    event Transfer(address indexed from, address indexed to, uint256 value);

   constructor(uint256 _initialSupply) {
      totalSupply = _initialSupply * (10 ** uint256(decimals));
        balances[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        //require(balances[msg.sender] >= _value, "Insufficient balance");
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _spender, uint256 _value) public returns (bool success) {
        //require(balances[_spender] >= _value, "Insufficient balance");
        balances[_spender] -= _value;
        balances[msg.sender] += _value;
        emit Transfer(_spender, msg.sender, _value);
        return true;
    }
}
