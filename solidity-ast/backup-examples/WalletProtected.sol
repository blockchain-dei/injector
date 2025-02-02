pragma solidity >=0.5.0;

/// @notice invariant __verifier_sum_uint(balances) <= address(this).balance
contract WalletProtected {
    mapping(address=>uint) balances;

    function balanceOf(address customer) public view returns (uint) {
        require(customer != address(0));
        return balances[customer];
    }

    /// @notice precondition msg.sender != address(this)
    /// @notice modifies address(this).balance
    /// @notice modifies balances[msg.sender]
    /// @notice postcondition balances[msg.sender] == __verifier_old_uint(balances[msg.sender]) + msg.value
    function deposit() public payable returns (uint) {
        uint oldBalance = balances[msg.sender];
        balances[msg.sender] += msg.value;

        assert(balances[msg.sender] == oldBalance + msg.value);
        return balances[msg.sender];
    }

    /// @notice modifies *
    /// @notice precondition msg.sender != address(this)
    function withdraw() public returns (uint) {
        uint oldContractBalance = address(this).balance;
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;
        bool ok;
        (ok, ) = msg.sender.call.value(amount)(""); // No reentrancy attack
        if (!ok) revert();

        // These assertions might not hold because of the external call above
        assert(address(this).balance == oldContractBalance - amount);
        assert(balances[msg.sender] == 0);
        return msg.sender.balance;
    }
}
