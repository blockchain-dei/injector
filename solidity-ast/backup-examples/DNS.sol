pragma solidity >=0.5.0;

// A domain name service contract, where users can register IP addresses
// for domain names.
contract DNS {
    struct Record {
        string ip;
        address owner;
    }
    
    mapping(string=>Record) records;
    address payable public owner;
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    constructor() public {
        owner = msg.sender;
    }
    
    function register(string memory domain, string memory ip) public payable {
        require(records[domain].owner == address(0x0) ||
                records[domain].owner == msg.sender);
        
        records[domain] = Record(ip, msg.sender);        
    }
    
    /**
     * @notice noinject
     */
    function lookup(string memory domain) public view returns (string memory) {
        return records[domain].ip;
    }
    
    function transfer(string memory domain, address newOwner) public {
        require(records[domain].owner == msg.sender);
        records[domain].owner = newOwner;
    }

    function shutdown() public onlyOwner {
        selfdestruct(owner);
    }
}