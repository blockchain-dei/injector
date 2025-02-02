var Abs = artifacts.require("Abs");

contract('Abs', function(accounts) {

  // To store the instance when running
  var a; 

  // Test case 1
  it("Test abs()", function() {
    return Abs.deployed().then(function(instance) {
      a = instance;
      return a.abs(-41, { from: accounts[0] });
    }).then(function(x) {
      // This is not a transaction (pure function)
      // so the result is simply the return value
      console.log(x);
      assert.equal(41, x.toNumber(), "Wrong abs");
    });
  });

  // Test case 2
  it("Test store()", function() {
    return Abs.deployed().then(function(instance) {
      a = instance;
      return a.store(182, { from: accounts[0] });
    }).then(function(x) {
      // This is a transaction so the result is
      // the receipt
      console.log(x);
    }).then(function() {
      return a.s();
    }).then(function(x) {
      // This is not a transaction (pure function)
      // so the result is simply the return value
      console.log(x);
    });
  });
});
