// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title InsuranceFund
 * @dev Training Contract #67 - DeFi Insurance Fund & Claims Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. False Claim Payout (INS-FALSECLAIM-01)
 * 2. Oracle-Triggered Claim Manipulation (INS-ORACLECLAIM-01)
 * 3. Premium Drain Before Payout (INS-PREMIUMDRAIN-01)
 * 4. Underwriting Pool Insolvency (INS-INSOLVENCY-01)
 * 5. Governance Vote Manipulation (INS-GOVVOTE-01)
 * 6. Coverage Stacking (INS-STACKING-01)
 * 7. Retrospective Coverage (INS-RETROACTIVE-01)
 * 8. Claim Assessor Collusion (INS-ASSESSOR-01)
 * 9. Premium Front-Running (INS-PREMIUMFRONT-01)
 * 10. Capital Efficiency Attack (INS-CAPEFFICIENCY-01)
 * 11. Reinsurance Cascade Failure (INS-REINSURANCE-01)
 * 12. Exploit-to-Claim Pipeline (INS-EXPLOIT2CLAIM-01)
 * 13. Time-Delayed Claim Gaming (INS-TIMECLAIM-01)
 * 14. Parametric Trigger Spoofing (INS-PARAMETRIC-01)
 * 15. Shield Mining Drain (INS-SHIELDMINE-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): INS-*, insurance, claim, premium, coverage
 * - Engine 2 (deep-semantic): claim logic, solvency, underwriting
 * - Engine 13 (mev-analyzer): premium front-running, timing attacks
 * - Engine 3 (state-desync): coverage state, premium accounting
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IPriceOracle {
    function getPrice(address asset) external view returns (uint256);
}

contract InsuranceFundProtocol {

    struct CoveragePolicy {
        address holder;
        address protectedProtocol;
        uint256 coverageAmount;
        uint256 premiumPaid;
        uint256 startTime;
        uint256 endTime;
        bool active;
        bool claimed;
    }

    struct Claim {
        uint256 policyId;
        address claimant;
        uint256 requestedAmount;
        uint256 approvedAmount;
        uint256 submittedTime;
        uint256 assessorVotes;
        uint256 rejectVotes;
        bool resolved;
        bool approved;
    }

    struct UnderwriterPosition {
        address underwriter;
        uint256 capitalDeposited;
        uint256 capitalLocked;
        uint256 premiumEarned;
        uint256 lastUpdateTime;
    }

    mapping(uint256 => CoveragePolicy) public policies;
    uint256 public nextPolicyId;
    mapping(uint256 => Claim) public claims;
    uint256 public nextClaimId;
    mapping(address => UnderwriterPosition) public underwriters;
    
    uint256 public totalCapital;
    uint256 public totalLockedCapital;
    uint256 public totalPremiums;
    uint256 public totalClaimsPaid;
    
    mapping(address => bool) public assessors;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    
    IPriceOracle public oracle;
    address public owner;
    uint256 public assessorQuorum = 3;
    uint256 public claimGracePeriod = 7 days;
    uint256 public maxCoverageRatio = 500; // 5x capital

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    // ========== VULN 1: False Claim Payout (INS-FALSECLAIM-01) ==========

    // BUG #1: claim approved by assessors without on-chain exploit verification
    function submitClaim(uint256 policyId, uint256 amount) external returns (uint256 claimId) {
        CoveragePolicy storage policy = policies[policyId];
        require(policy.holder == msg.sender, "not holder");
        require(policy.active, "not active");
        require(amount <= policy.coverageAmount, "exceeds coverage");
        
        // VULN: no on-chain verification that exploit actually happened
        // assessors vote based on off-chain evidence, easily faked
        claimId = nextClaimId++;
        claims[claimId] = Claim({
            policyId: policyId,
            claimant: msg.sender,
            requestedAmount: amount,
            approvedAmount: 0,
            submittedTime: block.timestamp,
            assessorVotes: 0,
            rejectVotes: 0,
            resolved: false,
            approved: false
        });
    }

    // ========== VULN 2: Oracle-Triggered Claim Manipulation (INS-ORACLECLAIM-01) ==========

    // BUG #2: parametric insurance triggered by oracle price drop
    function triggerParametricClaim(uint256 policyId) external {
        CoveragePolicy storage policy = policies[policyId];
        require(policy.active && !policy.claimed, "invalid");
        
        uint256 currentPrice = oracle.getPrice(policy.protectedProtocol);
        // VULN: attacker manipulates oracle price to trigger claim
        // flash loan → crash oracle price → trigger claim → oracle recovers
        require(currentPrice == 0 || currentPrice < 1e16, "no trigger event");
        
        policy.claimed = true;
        IERC20(policy.protectedProtocol).transfer(policy.holder, policy.coverageAmount);
    }

    // ========== VULN 3: Premium Drain Before Payout (INS-PREMIUMDRAIN-01) ==========

    // BUG #3: underwriters can withdraw premiums before claims are settled
    function withdrawPremiums() external {
        UnderwriterPosition storage pos = underwriters[msg.sender];
        uint256 earned = pos.premiumEarned;
        require(earned > 0, "nothing to withdraw");
        
        // VULN: premiums withdrawn but capital still needed for outstanding claims
        // underwriter withdraws premiums → fund can't pay claims
        pos.premiumEarned = 0;
        payable(msg.sender).transfer(earned);
    }

    // ========== VULN 4: Underwriting Pool Insolvency (INS-INSOLVENCY-01) ==========

    // BUG #4: total coverage sold exceeds available capital
    function buyCoverage(
        address protectedProtocol,
        uint256 coverageAmount,
        uint256 duration
    ) external payable returns (uint256 policyId) {
        uint256 premium = coverageAmount * duration * 5 / (365 days * 100); // 5% annual
        require(msg.value >= premium, "insufficient premium");
        
        // VULN: no check that total coverage <= totalCapital * maxCoverageRatio
        // fund sells $100M coverage on $10M capital
        // single large claim → insolvent
        policyId = nextPolicyId++;
        policies[policyId] = CoveragePolicy({
            holder: msg.sender,
            protectedProtocol: protectedProtocol,
            coverageAmount: coverageAmount,
            premiumPaid: msg.value,
            startTime: block.timestamp,
            endTime: block.timestamp + duration,
            active: true,
            claimed: false
        });
        
        totalPremiums += msg.value;
    }

    // ========== VULN 5: Governance Vote Manipulation (INS-GOVVOTE-01) ==========

    // BUG #5: claim approval by DAO vote, vote weight = deposit
    function voteOnClaim(uint256 claimId, bool approve_) external {
        require(underwriters[msg.sender].capitalDeposited > 0, "not underwriter");
        require(!hasVoted[claimId][msg.sender], "already voted");
        hasVoted[claimId][msg.sender] = true;
        
        Claim storage claim = claims[claimId];
        // VULN: one underwriter with 60% of capital controls all votes
        // can approve fake claims to drain fund
        if (approve_) {
            claim.assessorVotes++;
        } else {
            claim.rejectVotes++;
        }
    }

    // ========== VULN 6: Coverage Stacking (INS-STACKING-01) ==========

    // BUG #6: user buys multiple policies for same protocol
    function buyMultiplePolicies(
        address protocol, 
        uint256 coveragePerPolicy, 
        uint256 count
    ) external payable {
        for (uint256 i = 0; i < count; i++) {
            uint256 premium = coveragePerPolicy * 30 days * 5 / (365 days * 100);
            // VULN: same user stacks N policies, claims on all N
            // pays N premiums but gets N * coverageAmount if exploit occurs
            uint256 policyId = nextPolicyId++;
            policies[policyId] = CoveragePolicy({
                holder: msg.sender,
                protectedProtocol: protocol,
                coverageAmount: coveragePerPolicy,
                premiumPaid: premium,
                startTime: block.timestamp,
                endTime: block.timestamp + 30 days,
                active: true,
                claimed: false
            });
        }
    }

    // ========== VULN 7: Retrospective Coverage (INS-RETROACTIVE-01) ==========

    // BUG #7: coverage purchased after exploit but before public disclosure
    function buyCoverageForProtocol(address protocol) external payable returns (uint256) {
        // VULN: no check that protocol hasn't already been exploited
        // insider knows about exploit, buys coverage, then files claim
        uint256 id = nextPolicyId++;
        policies[id] = CoveragePolicy({
            holder: msg.sender,
            protectedProtocol: protocol,
            coverageAmount: msg.value * 10,
            premiumPaid: msg.value,
            startTime: block.timestamp,
            endTime: block.timestamp + 365 days,
            active: true,
            claimed: false
        });
        totalPremiums += msg.value;
        return id;
    }

    // ========== VULN 8: Claim Assessor Collusion (INS-ASSESSOR-01) ==========

    // BUG #8: assessors collude to approve/reject claims
    function assessorApprove(uint256 claimId, uint256 amount) external {
        require(assessors[msg.sender], "not assessor");
        Claim storage claim = claims[claimId];
        claim.assessorVotes++;
        
        // VULN: 3 assessors out of 5 can approve any claim
        // if 3 collude, they approve false claims and split proceeds
        if (claim.assessorVotes >= assessorQuorum) {
            claim.approved = true;
            claim.approvedAmount = amount;
            claim.resolved = true;
        }
    }

    // ========== VULN 9: Premium Front-Running (INS-PREMIUMFRONT-01) ==========

    // BUG #9: premium calculation based on current TVL via oracle
    function calculatePremium(address protocol, uint256 coverage, uint256 duration) 
        external view returns (uint256) 
    {
        uint256 protocolTVL = oracle.getPrice(protocol);
        uint256 riskFactor = coverage * 10000 / (protocolTVL + 1);
        // VULN: attacker sees coverage purchase in mempool
        // front-runs to manipulate oracle → premium calculation changes
        // or: buys coverage cheap before known exploit announcement
        return coverage * duration * riskFactor / (365 days * 10000);
    }

    // ========== VULN 10: Capital Efficiency Attack (INS-CAPEFFICIENCY-01) ==========

    // BUG #10: underwriter capital used as collateral elsewhere simultaneously
    function depositCapital() external payable {
        underwriters[msg.sender].capitalDeposited += msg.value;
        underwriters[msg.sender].lastUpdateTime = block.timestamp;
        totalCapital += msg.value;
        
        // VULN: underwriter can use receipt token as collateral in other protocol
        // same capital backs insurance AND borrows elsewhere
        // If insurance claim triggers, capital may be locked in other protocol
    }

    // ========== VULN 11: Reinsurance Cascade Failure (INS-REINSURANCE-01) ==========

    mapping(address => uint256) public reinsuranceAllocation;

    // BUG #11: reinsurance backed by another insurance fund
    function setReinsurance(address reinsurer, uint256 allocation) external {
        require(msg.sender == owner);
        // VULN: if reinsurer is also insolvent (same exploit affects both),
        // reinsurance claim fails → primary fund insolvent
        // circular reinsurance: A insures B insures A
        reinsuranceAllocation[reinsurer] = allocation;
    }

    // ========== VULN 12: Exploit-to-Claim Pipeline (INS-EXPLOIT2CLAIM-01) ==========

    // BUG #12: attacker exploits protocol THEN files insurance claim
    function fileExploitClaim(uint256 policyId, bytes calldata exploitProof) external {
        CoveragePolicy storage policy = policies[policyId];
        require(policy.holder == msg.sender, "not holder");
        
        // VULN: attacker IS the exploiter
        // 1. Buy insurance on protocol X (premium: 5%)
        // 2. Exploit protocol X (profit: 100%)
        // 3. File claim (payout: coverage amount)
        // Total profit: exploit + insurance payout - premium
        
        policy.claimed = true;
        // No check that claimant != exploiter
    }

    // ========== VULN 13: Time-Delayed Claim Gaming (INS-TIMECLAIM-01) ==========

    // BUG #13: claim filing window allows gaming
    function resolveClaim(uint256 claimId) external {
        Claim storage claim = claims[claimId];
        require(!claim.resolved, "already resolved");
        
        // VULN: if claim filed right before coverage expiry,
        // resolution happens after expiry but claim is still valid
        // also: waiting until claim grace period expires → auto-approve
        if (block.timestamp > claim.submittedTime + claimGracePeriod && !claim.resolved) {
            claim.approved = true; // Auto-approve after grace period
            claim.approvedAmount = claim.requestedAmount;
        }
        claim.resolved = true;
    }

    // ========== VULN 14: Parametric Trigger Spoofing (INS-PARAMETRIC-01) ==========

    mapping(address => uint256) public lastKnownTVL;

    // BUG #14: parametric insurance triggered by TVL drop
    function checkTrigger(address protocol) external returns (bool triggered) {
        uint256 currentTVL = oracle.getPrice(protocol);
        uint256 previousTVL = lastKnownTVL[protocol];
        
        // VULN: TVL drop of 50% triggers all policies for this protocol
        // attacker temporarily withdraws liquidity from protocol → TVL drops
        // trigger fires → claim paid → attacker re-deposits
        if (previousTVL > 0 && currentTVL < previousTVL / 2) {
            triggered = true;
        }
        lastKnownTVL[protocol] = currentTVL;
    }

    // ========== VULN 15: Shield Mining Drain (INS-SHIELDMINE-01) ==========

    mapping(address => uint256) public shieldMiningRewards;
    uint256 public rewardsPerSecond = 1e15;

    // BUG #15: shield mining incentivizes purchasing coverage for rewards
    function claimShieldRewards(uint256 policyId) external {
        CoveragePolicy storage policy = policies[policyId];
        require(policy.holder == msg.sender, "not holder");
        require(policy.active, "not active");
        
        uint256 elapsed = block.timestamp - policy.startTime;
        uint256 reward = elapsed * rewardsPerSecond * policy.coverageAmount / 1e18;
        
        // VULN: rewards may exceed premium paid
        // user buys cheapest coverage → mines rewards > premium cost
        // never intends to actually claim insurance → pure shield mining profit
        shieldMiningRewards[msg.sender] += reward;
        payable(msg.sender).transfer(reward);
    }

    // ========== Admin ==========

    function addAssessor(address assessor) external {
        require(msg.sender == owner);
        assessors[assessor] = true;
    }

    function payApprovedClaim(uint256 claimId) external {
        Claim storage claim = claims[claimId];
        require(claim.approved && claim.resolved, "not approved");
        require(claim.approvedAmount > 0, "zero amount");
        
        uint256 payout = claim.approvedAmount;
        claim.approvedAmount = 0;
        totalClaimsPaid += payout;
        payable(claim.claimant).transfer(payout);
    }

    receive() external payable {
        totalCapital += msg.value;
    }
}
