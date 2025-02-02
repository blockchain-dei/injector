'use strict';

const zeroAddress = '0x0000000000000000000000000000000000000000';

// addresses:
// [0]: owner address
// [1-5]: general address

function buildWorkload(c, a, evmContracts) {
	return [
        // get with owner/user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[1] ]},

        // get with user2 as invoker, with different addresses
        {type: 'q', invoker: c[1], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[1] ]},

        // set with owner as invoker, with non-zero value
        {type: 't', invoker: c[0], function: 'set', args: [ '10' ]},
        // set with owner as invoker, already set storage
        {type: 't', invoker: c[0], function: 'set', args: [ '10' ]},

        // set with user2 as invoker, with zero value
        {type: 't', invoker: c[1], function: 'set', args: [ '0' ]},
        // set with user2 as invoker, already set storage
        {type: 't', invoker: c[0], function: 'set', args: [ '-10' ]},

        // get with owner/user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[1] ]},

        // get with user2 as invoker, with different addresses
        {type: 'q', invoker: c[1], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[1] ]},

        // update with owner as invoker, with different values
        {type: 't', invoker: c[0], function: 'update', args: [ '10' ]},
        {type: 't', invoker: c[0], function: 'update', args: [ '0' ]},
        {type: 't', invoker: c[0], function: 'update', args: [ '-10' ]},

        // update with user2 as invoker, with different values
        {type: 't', invoker: c[1], function: 'update', args: [ '10' ]},
        {type: 't', invoker: c[1], function: 'update', args: [ '0' ]},
        {type: 't', invoker: c[1], function: 'update', args: [ '-10' ]},

        // update with user3 as invoker, with different values (storage not set yet)
        {type: 't', invoker: c[2], function: 'update', args: [ '10' ]},
        {type: 't', invoker: c[2], function: 'update', args: [ '0' ]},
        {type: 't', invoker: c[2], function: 'update', args: [ '-10' ]},

        // clear with owner as invoker, with different addresses
        {type: 't', invoker: c[0], function: 'clear', args: [ zeroAddress ]},
        {type: 't', invoker: c[0], function: 'clear', args: [ a[0] ]},
        {type: 't', invoker: c[0], function: 'clear', args: [ a[1] ]},

        // clear with user2 as invoker, with different addresses
        {type: 't', invoker: c[1], function: 'update', args: [ zeroAddress ]},
        {type: 't', invoker: c[1], function: 'update', args: [ a[1] ]},
        {type: 't', invoker: c[1], function: 'update', args: [ a[3] ]},

        // changeOwner by owner to own address
        {type: 't', invoker: c[0], function: 'changeOwner', args: [ a[0] ]},
        // changeOwner by user2 to own address
        {type: 't', invoker: c[1], function: 'changeOwner', args: [ a[1] ]},
        // changeOwner by user2 to other address
        {type: 't', invoker: c[1], function: 'changeOwner', args: [ a[2] ]},
        // changeOwner by user2 to zero address
        {type: 't', invoker: c[1], function: 'changeOwner', args: [ a[1] ]},
        // changeOwner by owner to user2
        {type: 't', invoker: c[0], function: 'changeOwner', args: [ a[1] ]},

        //////////////////////////
        // Repeat everything again (user2 is the new owner)
        //////////////////////////

        // get with user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[1] ]},

        // get with owner as invoker, with different addresses
        {type: 'q', invoker: c[1], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[1] ]},

        // set with user1 as invoker, with non-zero value
        {type: 't', invoker: c[0], function: 'set', args: [ '10' ]},
        // set with user1 as invoker, already set storage
        {type: 't', invoker: c[0], function: 'set', args: [ '10' ]},

        // set with owner as invoker, with zero value
        {type: 't', invoker: c[1], function: 'set', args: [ '0' ]},
        // set with owner as invoker, already set storage
        {type: 't', invoker: c[0], function: 'set', args: [ '-10' ]},

        // get with user1/user1 as invoker, with different addresses
        {type: 'q', invoker: c[0], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'get', args: [ a[1] ]},

        // get with owner as invoker, with different addresses
        {type: 'q', invoker: c[1], function: 'get', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'get', args: [ a[1] ]},

        // update with user1 as invoker, with different values
        {type: 't', invoker: c[0], function: 'update', args: [ '10' ]},
        {type: 't', invoker: c[0], function: 'update', args: [ '0' ]},
        {type: 't', invoker: c[0], function: 'update', args: [ '-10' ]},

        // update with owner as invoker, with different values
        {type: 't', invoker: c[1], function: 'update', args: [ '10' ]},
        {type: 't', invoker: c[1], function: 'update', args: [ '0' ]},
        {type: 't', invoker: c[1], function: 'update', args: [ '-10' ]},

        // update with user3 as invoker, with different values (storage not set yet)
        {type: 't', invoker: c[2], function: 'update', args: [ '10' ]},
        {type: 't', invoker: c[2], function: 'update', args: [ '0' ]},
        {type: 't', invoker: c[2], function: 'update', args: [ '-10' ]},

        // clear with user1 as invoker, with different addresses
        {type: 't', invoker: c[0], function: 'clear', args: [ zeroAddress ]},
        {type: 't', invoker: c[0], function: 'clear', args: [ a[0] ]},
        {type: 't', invoker: c[0], function: 'clear', args: [ a[1] ]},

        // clear with owner as invoker, with different addresses
        {type: 't', invoker: c[1], function: 'update', args: [ zeroAddress ]},
        {type: 't', invoker: c[1], function: 'update', args: [ a[1] ]},
        {type: 't', invoker: c[1], function: 'update', args: [ a[3] ]},

        // changeOwner by user1 to own address
        {type: 't', invoker: c[0], function: 'changeOwner', args: [ a[0] ]},
        // changeOwner by user1 to owner
        {type: 't', invoker: c[0], function: 'changeOwner', args: [ a[1] ]},
        // changeOwner by owner to own address
        {type: 't', invoker: c[1], function: 'changeOwner', args: [ a[1] ]},
        // changeOwner by owner to zero address
        {type: 't', invoker: c[1], function: 'changeOwner', args: [ a[1] ]},
        // changeOwner by owner to other address
        {type: 't', invoker: c[1], function: 'changeOwner', args: [ a[2] ]}
    ];
}

module.exports.buildWorkload = buildWorkload;
module.exports.workloadLength = 72;
