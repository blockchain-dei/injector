pragma solidity >=0.5.0;

/// @notice invariant __verifier_sum_uint(balances) <= address(this).balance
contract WalletStripped {
    mapping(address=>uint) balances;

    /// @notice postcondition r == balances[customer]
    function balanceOf(address customer) public view returns (uint r) {
        return balances[customer];
    }

    /// @notice modifies address(this).balance
    /// @notice modifies balances[msg.sender]
    /// @notice postcondition balances[msg.sender] == __verifier_old_uint(balances[msg.sender]) + msg.value
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice modifies *
    function withdraw() public {
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;
        bool ok;
        (ok, ) = msg.sender.call.value(amount)(""); // No reentrancy attack
        if (!ok) revert();
    }
}
