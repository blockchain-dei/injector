// From https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/payment/escrow
pragma solidity ^0.5.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }
}

contract Secondary {
    address internal _primary;

    /**
     * @dev Emitted when the primary contract changes.
     */
    event PrimaryTransferred(
        address recipient
    );

    /**
     * @dev Sets the primary account to the one that is creating the Secondary contract.
     * @notice noinject
     */
    constructor () internal {
        address msgSender = msg.sender;
        _primary = msgSender;
        emit PrimaryTransferred(msgSender);
    }

    /**
     * @dev Reverts if called from any account other than the primary.
     */
    modifier onlyPrimary() {
        require(msg.sender == _primary, "Secondary: caller is not the primary account");
        _;
    }

    /**
     * @return the address of the primary.
     * @notice postcondition a == _primary
     */
    function primary() public view returns (address a) {
        return _primary;
    }

    /**
     * @dev Transfers contract to a new primary.
     * @param recipient The address of new primary.
     *
     * @notice modifies _primary if msg.sender == __verifier_old_address(_primary)
     * @notice postcondition _primary == recipient
     */
    function transferPrimary(address recipient) public onlyPrimary returns (address) {
        require(recipient != address(0), "Secondary: new primary is the zero address");
        _primary = recipient;
        emit PrimaryTransferred(recipient);
        assert(_primary == recipient);
        return _primary;
    }
}

/// @notice invariant __verifier_sum_uint(_deposits) <= address(this).balance
contract Escrow is Secondary {
    using SafeMath for uint256;

    event Deposited(address indexed payee, uint256 weiAmount);
    event Withdrawn(address indexed payee, uint256 weiAmount);

    mapping(address => uint256) internal _deposits;

    function depositsOf(address payee) public view returns (uint256) {
        return _deposits[payee];
    }

    /**
     * @dev Stores the sent amount as credit to be withdrawn.
     * @param payee The destination address of the funds.
     *
     * @notice modifies _deposits[payee]
     * @notice modifies address(this).balance
     * @notice postcondition __verifier_old_uint(_deposits[payee]) == _deposits[payee] - msg.value
     */
    function deposit(address payee) public onlyPrimary payable returns (uint256) {
        uint256 amount = msg.value;
        uint256 oldAmount = _deposits[payee];
        _deposits[payee] = _deposits[payee].add(amount);

        emit Deposited(payee, amount);
        assert(_deposits[payee] == oldAmount.add(amount));
        return _deposits[payee];
    }

    /**
     * @dev Withdraw accumulated balance for a payee.
     * @param payee The address whose funds will be withdrawn and transferred to.
     *
     * @notice modifies _deposits[payee]
     * @notice modifies address(this).balance
     * @notice modifies payee.balance
     * @notice precondition payee != address(this)
     * @notice postcondition _deposits[payee] == 0
     */
    function withdraw(address payable payee) public onlyPrimary returns (uint256) {
        uint256 payment = _deposits[payee];
        uint256 oldBalance = payee.balance;
        _deposits[payee] = 0;
        payee.transfer(payment);

        emit Withdrawn(payee, payment);
        assert(_deposits[payee] == 0);
        assert(payee.balance == oldBalance.add(payment));
        return _deposits[payee];
    }
}

/**
 * @title ConditionalEscrow
 * @dev Base abstract escrow to only allow withdrawal if a condition is met.
 * @dev Intended usage: See {Escrow}. Same usage guidelines apply here.
 *
 * @notice invariant __verifier_sum_uint(_deposits) <= address(this).balance
 */
contract ConditionalEscrow is Escrow {
    /**
     * @dev Returns whether an address is allowed to withdraw their funds. To be
     * implemented by derived contracts.
     * @param payee The destination address of the funds.
     */
    function withdrawalAllowed(address payee) public view returns (bool);

    /**
     * @notice modifies _deposits[payee]
     * @notice modifies address(this).balance
     * @notice modifies payee.balance
     * @notice precondition payee != address(this)
     * @notice postcondition _deposits[payee] == 0
     */
    function withdraw(address payable payee) public returns (uint256) {
        require(withdrawalAllowed(payee), "ConditionalEscrow: payee is not allowed to withdraw");
        return super.withdraw(payee);
    }
}

/**
 * @title RefundEscrow
 * @dev Escrow that holds funds for a beneficiary, deposited from multiple
 * parties.
 * @dev Intended usage: See {Escrow}. Same usage guidelines apply here.
 * @dev The primary account (that is, the contract that instantiates this
 * contract) may deposit, close the deposit period, and allow for either
 * withdrawal by the beneficiary, or refunds to the depositors. All interactions
 * with `RefundEscrow` will be made through the primary contract. See the
 * `RefundableCrowdsale` contract for an example of `RefundEscrow`’s use.
 *
 * @notice invariant __verifier_sum_uint(_deposits) <= address(this).balance || _state == State.Closed
 */
contract RefundEscrowProtected is ConditionalEscrow {
    enum State { Active, Refunding, Closed }

    event RefundsClosed();
    event RefundsEnabled();

    State private _state;
    address payable private _beneficiary;

    /**
     * @dev Constructor.
     * @param beneficiary The beneficiary of the deposits.
     * @notice noinject
     */
    constructor (address payable beneficiary) public {
        require(beneficiary != address(0), "RefundEscrow: beneficiary is the zero address");
        _beneficiary = beneficiary;
        _state = State.Active;
    }

    /**
     * @return The current state of the escrow.
     */
    function state() public view returns (State) {
        return _state;
    }

    /**
     * @return The beneficiary of the escrow.
     * @notice postcondition a == _beneficiary
     */
    function beneficiary() public view returns (address a) {
        return _beneficiary;
    }

    /**
     * @dev Stores funds that may later be refunded.
     * @param refundee The address funds will be sent to if a refund occurs.
     *
     * @notice modifies _deposits[refundee] if __verifier_old_uint(uint(_state)) == uint(State.Active)
     * @notice modifies address(this).balance
     * @notice postcondition __verifier_old_uint(_deposits[refundee]) == _deposits[refundee] - msg.value
     */
    function deposit(address refundee) public payable returns (uint256) {
        require(_state == State.Active, "RefundEscrow: can only deposit while active");
        return super.deposit(refundee);
    }

    /**
     * @dev Allows for the beneficiary to withdraw their funds, rejecting
     * further deposits.
     *
     * @notice modifies _state if (__verifier_old_uint(uint(_state)) == uint(State.Active) && msg.sender == _primary)
     * @notice postcondition _state == State.Closed
     */
    function close() public onlyPrimary returns (State) {
        require(_state == State.Active, "RefundEscrow: can only close while active");
        _state = State.Closed;
        emit RefundsClosed();
        assert(_state == State.Closed);
        return _state;
    }

    /**
     * @dev Allows for refunds to take place, rejecting further deposits.
     *
     * @notice modifies _state if (__verifier_old_uint(uint(_state)) == uint(State.Active) && msg.sender == _primary)
     * @notice postcondition _state == State.Refunding
     */
    function enableRefunds() public onlyPrimary returns (State) {
        require(_state == State.Active, "RefundEscrow: can only enable refunds while active");
        _state = State.Refunding;
        emit RefundsEnabled();
        assert(_state == State.Refunding);
        return _state;
    }

    /**
     * @dev Withdraws the beneficiary's funds.
     * @notice modifies address(this).balance if _state == State.Closed
     * @notice modifies _beneficiary.balance if _state == State.Closed
     * @notice precondition _beneficiary != address(this)
     * @notice postcondition address(this).balance == 0
     * @notice postcondition _beneficiary.balance == __verifier_old_uint(_beneficiary.balance) + __verifier_old_uint(address(this).balance)
     */
    function beneficiaryWithdraw() public returns (uint256) {
        require(_state == State.Closed, "RefundEscrow: beneficiary can only withdraw while closed");
        uint256 oldBeneficiaryBalance = _beneficiary.balance;
        uint256 contractBalance = address(this).balance;

        _beneficiary.transfer(address(this).balance);

        assert(address(this).balance == 0);
        assert(_beneficiary.balance == oldBeneficiaryBalance.add(contractBalance));
        return address(this).balance;
    }

    /**
     * @dev Returns whether refundees can withdraw their deposits (be refunded). The overridden function receives a
     * 'payee' argument, but we ignore it here since the condition is global, not per-payee.
     *
     * @notice postcondition allowed == (_state == State.Refunding)
     */
    function withdrawalAllowed(address) public view returns (bool allowed) {
        return _state == State.Refunding;
    }
}