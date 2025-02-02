'use strict';

const zeroAddress = '0x0000000000000000000000000000000000000000';

// addresses:
// [0]: owner address
// [1-5]: general address

function buildWorkload(c, a, evmContracts) {
	return [
        // balanceOf with user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[1] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},

        // deposit
        {type: 't', invoker: c[0], function: 'deposit', weiValue: 0},
        {type: 't', invoker: c[0], function: 'deposit', weiValue: 1000},
        {type: 't', invoker: c[0], function: 'deposit', weiValue: 10000000000},
        // deposit all
        {type: 't', invoker: c[1], function: 'deposit', weiValue: 100000},

        // balanceOf with user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[1] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},

        // withdraw
        {type: 't', invoker: c[0], function: 'withdraw'},
        {type: 't', invoker: c[1], function: 'withdraw'},
        {type: 't', invoker: c[2], function: 'withdraw'},

        // balanceOf with user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[1] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]}
    ];
}

module.exports.buildWorkload = buildWorkload;
module.exports.workloadLength = 19;
