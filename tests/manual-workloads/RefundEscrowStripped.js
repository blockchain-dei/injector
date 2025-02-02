'use strict';

const zeroAddress = '0x0000000000000000000000000000000000000000';

// addresses:
// [0]: primary address
// [1]: beneficiary address
// [2-5]: general address

function buildWorkload(c, a, evmContracts) {
	return [
	    ///////////////////
        // STATE: ACTIVE //
        ///////////////////

        // QUERY: primary
        {type: 'q', invoker: c[0], function: 'primary', args: []},
        {type: 'q', invoker: c[1], function: 'primary', args: []},
        {type: 'q', invoker: c[2], function: 'primary', args: []},

        // QUERY: state
        {type: 'q', invoker: c[0], function: 'state', args: []},
        {type: 'q', invoker: c[1], function: 'state', args: []},
        {type: 'q', invoker: c[2], function: 'state', args: []},

        // QUERY: beneficiary
        {type: 'q', invoker: c[0], function: 'beneficiary', args: []},
        {type: 'q', invoker: c[1], function: 'beneficiary', args: []},
        {type: 'q', invoker: c[2], function: 'beneficiary', args: []},

        // QUERY: depositsOf
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ a[1] ]},
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ a[1] ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ a[2] ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ a[1] ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ zeroAddress ]},

        // QUERY: withdrawalAllowed
        // arg is ignored in contract
        {type: 'q', invoker: c[0], function: 'withdrawalAllowed', args: [ a[1] ]},
        {type: 'q', invoker: c[1], function: 'withdrawalAllowed', args: [ a[1] ]},
        {type: 'q', invoker: c[2], function: 'withdrawalAllowed', args: [ a[1] ]},

        // TRANSACTION: deposit
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[0] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[0] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[0] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[1] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[1] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[1] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[2] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[2] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[2] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ zeroAddress ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ zeroAddress ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ zeroAddress ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[0] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[0] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[0] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[1] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[1] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[1] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[2] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[2] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[2] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ zeroAddress ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ zeroAddress ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ zeroAddress ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[0] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[0] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[0] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[1] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[1] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[1] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[2] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[2] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[2] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ zeroAddress ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ zeroAddress ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ zeroAddress ], weiValue: 10000000000}, // lot of wei

        // TRANSACTION: transferPrimary
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ a[0] ]},
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ a[1] ]},
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ a[2] ]},
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ zeroAddress ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ a[0] ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ a[1] ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ a[2] ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ zeroAddress ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ a[0] ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ a[1] ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ a[2] ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ zeroAddress ]},

        // TRANSACTION: withdraw
        {type: 't', invoker: c[0], function: 'withdraw', args: [ a[0] ]},
        {type: 't', invoker: c[0], function: 'withdraw', args: [ a[1] ]},
        {type: 't', invoker: c[0], function: 'withdraw', args: [ a[2] ]},
        {type: 't', invoker: c[0], function: 'withdraw', args: [ zeroAddress ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ a[0] ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ a[1] ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ a[2] ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ zeroAddress ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ a[0] ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ a[1] ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ a[2] ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ zeroAddress ]},

        // TRANSACTION: beneficiaryWithdraw
        {type: 't', invoker: c[0], function: 'beneficiaryWithdraw', args: []},
        {type: 't', invoker: c[1], function: 'beneficiaryWithdraw', args: []},
        {type: 't', invoker: c[2], function: 'beneficiaryWithdraw', args: []},

        // TRANSACTION: close
        // TRANSITIONS TO "CLOSED" STATE
        {type: 't', invoker: c[1], function: 'close', args: []},
        {type: 't', invoker: c[2], function: 'close', args: []},
        {type: 't', invoker: c[0], function: 'close', args: []}, // call with primary at the end

        // Disabled, not in "ACTIVE" anymore
        // // TRANSACTION: enableRefunds
        // // TRANSITIONS TO "REFUNDING" STATE
        // {type: 't', invoker: c[1], function: 'enableRefunds', args: []},
        // {type: 't', invoker: c[2], function: 'enableRefunds', args: []},
        // {type: 't', invoker: c[0], function: 'enableRefunds', args: []}, // call with primary at the end

        /////////////////////////////
        // STATE: CLOSED/REFUNDING //
        /////////////////////////////

        // QUERY: primary
        {type: 'q', invoker: c[0], function: 'primary', args: []},
        {type: 'q', invoker: c[1], function: 'primary', args: []},
        {type: 'q', invoker: c[2], function: 'primary', args: []},

        // QUERY: state
        {type: 'q', invoker: c[0], function: 'state', args: []},
        {type: 'q', invoker: c[1], function: 'state', args: []},
        {type: 'q', invoker: c[2], function: 'state', args: []},

        // QUERY: beneficiary
        {type: 'q', invoker: c[0], function: 'beneficiary', args: []},
        {type: 'q', invoker: c[1], function: 'beneficiary', args: []},
        {type: 'q', invoker: c[2], function: 'beneficiary', args: []},

        // QUERY: depositsOf
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ a[1] ]},
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'depositsOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ a[1] ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ a[2] ]},
        {type: 'q', invoker: c[1], function: 'depositsOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ a[1] ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'depositsOf', args: [ zeroAddress ]},

        // QUERY: withdrawalAllowed
        // arg is ignored in contract
        {type: 'q', invoker: c[0], function: 'withdrawalAllowed', args: [ a[1] ]},
        {type: 'q', invoker: c[1], function: 'withdrawalAllowed', args: [ a[1] ]},
        {type: 'q', invoker: c[2], function: 'withdrawalAllowed', args: [ a[1] ]},

        // TRANSACTION: deposit
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[0] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[0] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[0] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[1] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[1] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[1] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[2] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[2] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ a[2] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ zeroAddress ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ zeroAddress ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[0], function: 'deposit', args: [ zeroAddress ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[0] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[0] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[0] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[1] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[1] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[1] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[2] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[2] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ a[2] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ zeroAddress ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ zeroAddress ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[1], function: 'deposit', args: [ zeroAddress ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[0] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[0] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[0] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[1] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[1] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[1] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[2] ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[2] ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ a[2] ], weiValue: 10000000000}, // lot of wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ zeroAddress ], weiValue: 0}, // zero wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ zeroAddress ], weiValue: 1000}, // few wei
        {type: 't', invoker: c[2], function: 'deposit', args: [ zeroAddress ], weiValue: 10000000000}, // lot of wei

        // TRANSACTION: transferPrimary
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ a[0] ]},
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ a[1] ]},
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ a[2] ]},
        {type: 't', invoker: c[0], function: 'transferPrimary', args: [ zeroAddress ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ a[0] ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ a[1] ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ a[2] ]},
        {type: 't', invoker: c[1], function: 'transferPrimary', args: [ zeroAddress ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ a[0] ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ a[1] ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ a[2] ]},
        {type: 't', invoker: c[2], function: 'transferPrimary', args: [ zeroAddress ]},

        // TRANSACTION: withdraw
        {type: 't', invoker: c[0], function: 'withdraw', args: [ a[0] ]},
        {type: 't', invoker: c[0], function: 'withdraw', args: [ a[1] ]},
        {type: 't', invoker: c[0], function: 'withdraw', args: [ a[2] ]},
        {type: 't', invoker: c[0], function: 'withdraw', args: [ zeroAddress ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ a[0] ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ a[1] ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ a[2] ]},
        {type: 't', invoker: c[1], function: 'withdraw', args: [ zeroAddress ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ a[0] ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ a[1] ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ a[2] ]},
        {type: 't', invoker: c[2], function: 'withdraw', args: [ zeroAddress ]},

        // TRANSACTION: beneficiaryWithdraw
        {type: 't', invoker: c[0], function: 'beneficiaryWithdraw', args: []},
        {type: 't', invoker: c[1], function: 'beneficiaryWithdraw', args: []},
        {type: 't', invoker: c[2], function: 'beneficiaryWithdraw', args: []},

        // TRANSACTION: close
        {type: 't', invoker: c[0], function: 'close', args: []},
        {type: 't', invoker: c[1], function: 'close', args: []},
        {type: 't', invoker: c[2], function: 'close', args: []},

        // TRANSACTION: enableRefunds
        {type: 't', invoker: c[0], function: 'enableRefunds', args: []},
        {type: 't', invoker: c[1], function: 'enableRefunds', args: []},
        {type: 't', invoker: c[2], function: 'enableRefunds', args: []}
	];
}

module.exports.ctrInit = ['$USER_1'];
module.exports.buildWorkload = buildWorkload;
module.exports.workloadLength = 183;
