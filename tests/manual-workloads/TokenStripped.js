'use strict';

const zeroAddress = '0x0000000000000000000000000000000000000000';

// addresses:
// [0]: creator address
// [1-5]: general address

function buildWorkload(c, a, evmContracts) {
	return [
	    // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // balanceOf with user2 as invoker
        {type: 'q', invoker: c[1], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[1], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[1], function: 'balanceOf', args: [ a[2] ]},

        // transfer with creator as invoker
        // receiver is zero address, with different values
        {type: 't', invoker: c[0], function: 'transfer', args: [ zeroAddress, '0' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ zeroAddress, '1' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ zeroAddress, Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ zeroAddress, Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // transfer with creator as invoker
        // receiver is own address, with different values
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[0], '0' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[0], '1' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[0], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[0], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // transfer with creator as invoker
        // receiver is user3, with different values
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[2], '0' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[2], '1' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[2], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[2], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // transfer with creator as invoker
        // receiver is user4, with different values
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[3], '0' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[3], '1' ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[3], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'transfer', args: [ a[3], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receiver is empty, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receiver is zero address, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [zeroAddress], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [zeroAddress], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [zeroAddress], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [zeroAddress], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receiver is own address, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[0]], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[0]], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[0]], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[0]], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receiver is another address, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2]], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2]], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2]], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2]], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receivers have zero address, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], zeroAddress], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], zeroAddress], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], zeroAddress], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], zeroAddress], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receivers have own address, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], a[0]], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], a[0]], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], a[0]], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[2], a[0]], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with creator as invoker
        // receivers have own and zero address, with different values
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], '0' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], '1' ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], Math.pow(10, 11).toString(10) ]},

        // balanceOf with creator/user1 as invoker
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[0], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receiver is empty, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receiver is zero address, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [zeroAddress], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [zeroAddress], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [zeroAddress], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [zeroAddress], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receiver is own address, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[0]], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[0]], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[0]], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[0]], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receiver is another address, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2]], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2]], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2]], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2]], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receivers have zero address, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], zeroAddress], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], zeroAddress], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], zeroAddress], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], zeroAddress], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receivers have own address, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], a[0]], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], a[0]], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], a[0]], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[2], a[0]], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // receivers have own and zero address, with different values
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], '0' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], '1' ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], Math.pow(2, 10).toString(10) ]},
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[3], a[0], zeroAddress], Math.pow(10, 11).toString(10) ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user3 as invoker
        // overflow
        {type: 't', invoker: c[2], function: 'batchTransfer', args: [ [a[0], a[1], a[3], a[4]], '28948022309329048855892746252171976963317496166410141009864396001978282409984' ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]},

        // batchTransfer with user1 as invoker
        // overflow
        {type: 't', invoker: c[0], function: 'batchTransfer', args: [ [a[1], a[2], a[3], a[4]], '28948022309329048855892746252171976963317496166410141009864396001978282409984' ]},

        // balanceOf with user3 as invoker
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ zeroAddress ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[0] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[2] ]},
        {type: 'q', invoker: c[2], function: 'balanceOf', args: [ a[3] ]}
	];
}

module.exports.buildWorkload = buildWorkload;
module.exports.workloadLength = 151;
