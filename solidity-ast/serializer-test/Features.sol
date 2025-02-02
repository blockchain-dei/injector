pragma solidity >=0.5.0;

contract Features {

    uint private c = 5;

    modifier withParam(int x) {
        require(x > 0);
        _;
    }

    function whileLoop(int x, int y) public pure returns (int) {
        while (x != y) {
            if (y < 0) break;
            if (x > y) x--;
            else x++;
        }
        if (x != y) revert();
        return x;
    }

    function test(int y) public pure withParam(y) {
        int z = y > 0 ? y : -y;
        whileLoop(1, z);
    }
}

contract Sub is Features {
    
}