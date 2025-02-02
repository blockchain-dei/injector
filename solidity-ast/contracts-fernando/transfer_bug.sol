pragma solidity >=0.4.25;
contract 
Gamble{
address owner;
address[] members;
address[] participators;
uint participatorID = 0;
modifier onlyOwner 
{
    // Transaction State Dependency
    require (tx.origin == owner ) ;
    _;
}

constructor() 
{ // constructor function
  owner =  0xfbb61B8b98a59FbC4bD79C23212AddbEFaEB289f; // this is the address of tx. origin
}

function receiver() public payable
{ // Executed when receiving Ethers
    ReceiveEth (); 
}

 function ReceiveEth() public payable
 { 
    if(msg.value!=1 ether)
        { revert();}//msg.value is the number of received ETHs
    members.push(msg.sender); 
    participators[participatorID] = msg.sender; 
    participatorID ++;
    if(address(this).balance==10 ether){ // Strict Balance Equality 
        //Strict Balance Equality 
        getWinner () ;}
}

function getWinner() public
{ //choose a member to be the winner
  uint winnerID = uint (block.blockhash(block.number)) % participators.length; 
 // participators[winnerID].send(8 ether); 
  participatorID = 0;
}

function giveBonus() public returns(bool){  //send 0.1 ETH to all members as bonus
//∗ Unmatched Type Assignment , Nested Call ∗/ 
for(int i=0;i < members.length; i++)
{
    if ( this.balance > 0.1 ether)
       members[i].transfer(0.1 ether) ; //∗DoS Under External Influence ∗/   } 
    
//∗ Missing Return Statement ∗/
 }
}

function suicide(address addr) public onlyOwner
{ //Remove the contract from blockchain
    selfdestruct (addr) 
;}

function withDraw( uint amount) public onlyOwner
{ 
 //withdraw certain Ethers to owner account address receiver = 0xcDA0D6adCD0f1CCeA6795F9b1F23a27ae643FE7C;
 receiver.call.value(amount);
 }

}



//The difference between transfer and send is that transfer will throw an exception and terminate the transaction if the Ether fails to send, while send will return a boolean value instead of throwing an exception




