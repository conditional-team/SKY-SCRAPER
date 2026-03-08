// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title NegativeSpaceDAO
 * @dev Training Contract #5 - Negative Space + Missing Validations
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. No event emitted on critical state changes
 * 2. Return values never checked
 * 3. State variable set but never decremented
 * 4. Mapping entries never deleted
 * 5. Zero address not validated on transfers
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 8: Negative Space Finder
 * - Engine 25: Finality Checker (resettable state)
 * - Engine 11: Caller Myth Analyzer
 * - Engine 9: Invariant Chain
 * 
 * COMBO: B1 Negative Space × Trusted Silence
 */

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract NegativeSpaceDAO {
    // === STATE ===
    address public governance;
    
    struct Proposal {
        uint256 id;
        address proposer;
        string description;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        // BUG #1: No 'cancelled' field - cancelled proposals still exist
    }
    
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    // BUG #2: hasVoted never deleted - votes persist forever
    
    mapping(address => uint256) public votingPower;
    // BUG #3: votingPower only increases, never decreases
    
    mapping(address => uint256) public delegatedTo;
    // BUG #4: Weird mapping - uint256 not address, never used correctly
    
    uint256 public proposalCount;
    uint256 public quorum;
    
    // BUG #5: These are set but NEVER reset
    uint256 public lastProposalTime;
    uint256 public totalProposalsCreated;
    
    // BUG #6: Emergency state - set to true, never set back to false
    bool public emergencyMode;
    
    // === NO EVENTS FOR CRITICAL OPERATIONS ===
    // BUG #7: Missing events for: vote, cancel, emergency, power change

    modifier onlyGovernance() {
        require(msg.sender == governance, "Not governance");
        _;
    }

    constructor(uint256 _quorum) {
        governance = msg.sender;
        quorum = _quorum;
        votingPower[msg.sender] = 1000;
    }

    /**
     * @dev Create proposal
     * BUG #8: No event emitted
     */
    function propose(string calldata description, uint256 duration) external returns (uint256) {
        require(votingPower[msg.sender] >= 100, "Insufficient power");
        
        proposalCount++;
        uint256 proposalId = proposalCount;
        
        proposals[proposalId] = Proposal({
            id: proposalId,
            proposer: msg.sender,
            description: description,
            forVotes: 0,
            againstVotes: 0,
            startBlock: block.number,
            endBlock: block.number + duration,
            executed: false
        });
        
        // BUG #9: These only increase, create false metric
        lastProposalTime = block.timestamp;
        totalProposalsCreated++;
        
        // NO EVENT
        return proposalId;
    }

    /**
     * @dev Vote on proposal
     * BUG #10: hasVoted[proposalId][voter] = true, but never deleted on cancel
     */
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.number <= proposal.endBlock, "Voting ended");
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        
        hasVoted[proposalId][msg.sender] = true;
        // BUG: Never deleted even if proposal cancelled
        
        uint256 power = votingPower[msg.sender];
        if (support) {
            proposal.forVotes += power;
        } else {
            proposal.againstVotes += power;
        }
        
        // NO EVENT - silent voting
    }

    /**
     * @dev Execute proposal
     * BUG #11: executed = true but proposal struct stays forever
     */
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.number > proposal.endBlock, "Voting not ended");
        require(!proposal.executed, "Already executed");
        require(proposal.forVotes >= quorum, "Quorum not reached");
        require(proposal.forVotes > proposal.againstVotes, "Not passed");
        
        proposal.executed = true;
        // BUG: Proposal data stays in mapping forever
        // No cleanup, no deletion
        
        // NO EVENT
    }

    /**
     * @dev Cancel proposal - but doesn't clean up
     * BUG #12: No 'cancelled' state, just deletes struct but hasVoted remains
     */
    function cancelProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(msg.sender == proposal.proposer || msg.sender == governance, "Not authorized");
        
        // "Delete" proposal - but hasVoted mapping still has entries!
        delete proposals[proposalId];
        
        // BUG: hasVoted[proposalId] entries still exist
        // If same proposalId is reused, old voters can't vote
        
        // NO EVENT
    }

    /**
     * @dev Grant voting power
     * BUG #13: Power only granted, never revoked via this function
     */
    function grantVotingPower(address user, uint256 amount) external onlyGovernance {
        votingPower[user] += amount; // Only increases
        // NO EVENT
    }

    /**
     * @dev Emergency mode - can be enabled, never disabled
     * BUG #14: emergencyMode = true is permanent
     */
    function enableEmergency() external onlyGovernance {
        emergencyMode = true;
        // BUG: No function to set back to false
        // NO EVENT
    }

    /**
     * @dev Emergency withdraw
     * BUG #15: Transfer return value not checked
     */
    function emergencyWithdraw(address token, address to, uint256 amount) external onlyGovernance {
        require(emergencyMode, "Not emergency");
        
        // BUG #16: Zero address check missing
        // to could be address(0)
        
        // BUG #17: Return value IGNORED
        IERC20Minimal(token).transfer(to, amount);
        
        // NO EVENT for emergency withdrawal!
    }

    /**
     * @dev Deposit tokens for voting power
     * BUG #18: TransferFrom return value not checked
     */
    function depositForPower(address token, uint256 amount) external {
        // BUG: Return value ignored - deposit might fail silently
        IERC20Minimal(token).transferFrom(msg.sender, address(this), amount);
        
        // Power granted even if transfer failed!
        votingPower[msg.sender] += amount;
        
        // NO EVENT
    }

    /**
     * @dev Get proposal - seems safe but exposes internal data
     */
    function getProposal(uint256 proposalId) external view returns (Proposal memory) {
        return proposals[proposalId];
    }

    /**
     * @dev Check if address has voted
     */
    function hasUserVoted(uint256 proposalId, address user) external view returns (bool) {
        return hasVoted[proposalId][user];
        // BUG: Returns true even for cancelled proposals
    }
}
