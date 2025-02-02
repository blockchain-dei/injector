pragma solidity >=0.5.0;

/// @notice invariant totalSupply == __verifier_sum_uint(balances)
contract TokenStripped {
    uint256 public totalSupply;
    mapping(address => uint256) balances;

    /// @notice noinject
    constructor() public {
        totalSupply = (10**10);
        balances[msg.sender] = totalSupply; // Give the creator all initial tokens
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    /// @notice modifies balances[msg.sender] if msg.sender != _receiver
    /// @notice modifies balances[_receiver] if msg.sender != _receiver
    /// @notice postcondition msg.sender == _receiver || __verifier_old_uint(balances[msg.sender]) - _value == balances[msg.sender]
    /// @notice postcondition msg.sender == _receiver || __verifier_old_uint(balances[_receiver]) == balances[_receiver] - _value
    /// @notice postcondition msg.sender != _receiver || __verifier_old_uint(balances[msg.sender]) == balances[msg.sender]
    /// @notice postcondition msg.sender != _receiver || __verifier_old_uint(balances[_receiver]) == balances[_receiver]
    function transfer(address _receiver, uint256 _value) public returns (bool) {
        balances[msg.sender] = balances[msg.sender] - _value;
        balances[_receiver] = balances[_receiver] + _value;
        return true;
    }

    /// @notice modifies *
    function batchTransfer(address[] memory _receivers, uint256 _value) public returns (bool) {
        uint cnt = _receivers.length;
        uint256 amount = uint256(cnt) * _value;

        balances[msg.sender] = balances[msg.sender] - amount;
        /// @notice invariant totalSupply == __verifier_sum_uint(balances) + (cnt - i) * _value
        /// @notice invariant i <= cnt
        for (uint i = 0; i < cnt; i++) {
            balances[_receivers[i]] = balances[_receivers[i]] + _value;
        }
        return true;
    }
}