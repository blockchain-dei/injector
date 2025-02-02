pragma solidity >=0.5.0 ;

contract Abs {
    int8 public s;

    function store(int8  _s) public    {
        s = _s;
    }


    function abs(int8  x) public pure returns ( int8  )    {
        int8  y = x;
        if ((y < 0)) y *= -1;
        assert((y >= 0));
    }


}
