pragma solidity ^0.7.0 ;

contract Ballot {
    struct Voter {
    uint  weight;
    bool  voted;
    address  delegate;
    uint  vote;
    }

    struct Proposal {
    bytes32  name;
    uint  voteCount;
    }

    address public chairperson;

    mapping(address => Voter) public voters;

    Proposal[] public proposals;

    constructor(bytes32[] memory proposalNames) public    {
        chairperson = msg.sender;
        voters[chairperson].weight = 1;
        for (uint32  i = 0; (i < proposalNames.length); i++) {
                proposals.push(Proposal(proposalNames[i], 0));
            }
    }
    
    /**
     * @dev Give 'voter' the right to vote on this ballot. May only be called by 'chairperson'.
     *  @param voter address of voter
     */
    function giveRightToVote(address  voter) public    {
        require((msg.sender == chairperson), "Only chairperson can give right to vote.");
        require(!voters[voter].voted, "The voter already voted.");
        require((voters[voter].weight == 0));
        voters[voter].weight = 1;
    }


    /**
     * @dev Delegate your vote to the voter 'to'.
     *  @param to address to which vote is delegated
     */
    function delegate(address  to) public    {
        Voter storage sender = voters[msg.sender];
        require(!sender.voted, "You already voted.");
        require((to != msg.sender), "Self-delegation is disallowed.");
        sender.voted = true;
        sender.delegate = to;
        Voter storage delegate_ = voters[to];
        if (delegate_.voted)
            {
                proposals[delegate_.vote].voteCount += sender.weight;
            }
        else 
            {
                delegate_.weight += sender.weight;
            }
    }


    /**
     * @dev Give your vote (including votes delegated to you) to proposal 'proposals[proposal].name'.
     *  @param proposal index of proposal in the proposals array
     */
    function vote(uint  proposal) public    {
        Voter storage sender = voters[msg.sender];
        require((sender.weight != 0), "Has no right to vote");
        require(!sender.voted, "Already voted.");
        sender.voted = true;
        sender.vote = proposal;
        proposals[proposal].voteCount += sender.weight;
    }


    /**
     * @dev Computes the winning proposal taking all previous votes into account.
     *  @return winningProposal_ index of winning proposal in the proposals array
     */
    function winningProposal() public view returns ( uint  winningProposal_)    {
        uint  winningVoteCount = 0;
        for (uint  p = 0; (p < proposals.length); p++) {
                if ((proposals[p].voteCount > winningVoteCount))
                    {
                        winningVoteCount = proposals[p].voteCount;
                        winningProposal_ = p;
                    }
            }
    }


    /**
     * @dev Calls winningProposal() function to get the index of the winner contained in the proposals array and then
     *  @return winnerName_ the name of the winner
     */
    function winnerName() public view returns ( bytes32  winnerName_)    {
        winnerName_ = proposals[winningProposal()].name;
        return winnerName_;
    }


}
