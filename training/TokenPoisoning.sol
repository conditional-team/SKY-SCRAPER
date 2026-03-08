// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TokenPoisoning
 * @dev Training Contract #21 - Token Interaction & Approval Vulnerabilities
 * 
 * VULNERABILITY CATEGORIES:
 * 1. Address poisoning via zero-value transfers (phantom tx history)
 * 2. Approval race condition (front-running approve())
 * 3. Fee-on-transfer token assumptions (received != sent)
 * 4. Rebasing token balance desync (balance changes without transfer)
 * 5. Token callback hooks (ERC-777-like reentrancy via tokensReceived)
 * 6. Infinite approval + Permit2 chain attacks
 * 7. Governance flash loan (borrow â†’ vote â†’ return in 1 tx)
 * 8. Return value handling (non-standard ERC-20 returns)
 * 9. Double-spend via transferFrom + permit race
 * 10. Donation attack on share-based vaults
 *
 * REAL-WORLD EXAMPLES:
 * - Address poisoning: $68M lost (2024, copied wrong address from tx history)
 * - Fee-on-transfer: SushiSwap MasterChef bug
 * - Rebasing: Ampleforth integration failures
 * - Governance flash: Beanstalk $182M exploit
 * - Approval race: Known ERC-20 front-running issue
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 6: Token Flow (fee-on-transfer, rebasing detection)
 * - Engine 12: Reentrancy (token callback hooks)
 * - Engine 4: Temporal (approval race conditions)
 * - Engine 9: Access Control (governance attacks)
 * - Engine 17: Cross-Contract (approval chain attacks)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 01_PrecisionVault (share inflation via donation)
 * - Links to 07_FlashLoanVictim (flash loan governance attack)
 * - Links to 06_CallbackReentrancy (token callback reentrancy)
 */

// ========== TOKEN INTERFACES ==========

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    function nonces(address owner) external view returns (uint256);
}

interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

// ðŸ”— CHAIN: Links to existing contracts
interface IPrecisionVault {
    function deposit(uint256 assets) external returns (uint256 shares);
    function withdraw(uint256 shares) external returns (uint256 assets);
    function totalSupply() external view returns (uint256);
    function virtualPrice() external view returns (uint256);
}

interface IFlashLoanVictim {
    function flashLoan(uint256 amount) external;
    function getPrice() external view returns (uint256);
}

// ========== MAIN CONTRACT ==========

contract TokenPoisoning {
    // === STATE ===
    
    address public owner;
    
    // Multi-token vault
    mapping(address => mapping(address => uint256)) public userDeposits; // token => user => amount
    mapping(address => uint256) public totalTokenDeposits; // token => total
    mapping(address => bool) public supportedTokens;
    
    // Governance
    mapping(address => uint256) public votingPower;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public quorum;
    
    // Approvals
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => uint256) public nonces;
    
    // Share tracking
    mapping(address => mapping(address => uint256)) public userShares; // token => user => shares
    mapping(address => uint256) public totalShares; // token => total shares
    
    // Rebasing token snapshot
    mapping(address => uint256) public lastKnownBalance; // token => last balance
    
    // ðŸ”— CHAIN: External contracts
    IPrecisionVault public precisionVault;
    IFlashLoanVictim public flashLoanVictim;
    
    // Address registry (for poisoning)
    mapping(address => address[]) public userTransferHistory;
    mapping(address => address) public lastRecipient;
    
    struct Proposal {
        string description;
        address target;
        bytes callData;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 endBlock;
        bool executed;
        mapping(address => bool) hasVoted;
    }
    
    event Deposit(address indexed token, address indexed user, uint256 amount);
    event Withdrawal(address indexed token, address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    
    constructor(uint256 _quorum) {
        owner = msg.sender;
        quorum = _quorum;
    }
    
    function setExternalContracts(address _vault, address _flashLoan) external {
        // BUG: No access control
        precisionVault = IPrecisionVault(_vault);
        flashLoanVictim = IFlashLoanVictim(_flashLoan);
    }
    
    function addSupportedToken(address token) external {
        require(msg.sender == owner, "Not owner");
        supportedTokens[token] = true;
    }

    // ========== VULNERABILITY #1: ADDRESS POISONING ==========
    
    /**
     * @dev Transfer with address history tracking
     * BUG #1: Zero-value transfers create fake tx history
     * Attacker sends 0 tokens from lookalike address â†’ user copies wrong address
     * 
     * Real attack: Attacker creates address 0xAbC...123 similar to victim's 0xAbC...789
     * Sends zero-value transfer â†’ appears in victim's tx history
     * Victim copies attacker's address for next large transfer
     */
    function transfer(address token, address to, uint256 amount) external {
        // BUG #1: No minimum transfer amount!
        // Zero-value transfers are valid and recorded in history
        // Attacker can poison any user's transfer history for free
        
        if (amount > 0) {
            // BUG #8: Return value not checked for non-standard tokens
            IERC20(token).transferFrom(msg.sender, to, amount);
        }
        // Even for amount=0, we record the transfer history
        
        // BUG #1: This creates a poisoned history entry
        userTransferHistory[msg.sender].push(to);
        lastRecipient[msg.sender] = to;
        
        emit Transfer(msg.sender, to, amount);
    }
    
    /**
     * @dev Quick send to last recipient
     * BUG #1b: User trusts lastRecipient from potentially poisoned history
     */
    function sendToLastRecipient(address token, uint256 amount) external {
        address to = lastRecipient[msg.sender];
        require(to != address(0), "No history");
        
        // BUG #1b: to could be attacker's lookalike address from zero-value poison!
        IERC20(token).transferFrom(msg.sender, to, amount);
        
        emit Transfer(msg.sender, to, amount);
    }

    // ========== VULNERABILITY #2: APPROVAL RACE CONDITION ==========
    
    /**
     * @dev Standard approve - VULNERABLE to front-running
     * BUG #2: Changing approval from N to M allows spending N+M total
     * 
     * Attack: Alice approves Bob for 100. Later changes to 50.
     * Bob sees the tx in mempool â†’ front-runs â†’ spends 100 (old approval)
     * Alice's tx executes â†’ approval now 50 â†’ Bob spends 50 more
     * Total spent: 150 instead of max 50
     */
    function approve(address token, address spender, uint256 amount) external {
        // BUG #2: Direct set without checking current allowance
        // Should use increaseAllowance/decreaseAllowance pattern
        allowances[msg.sender][spender] = amount;
        
        // No check that old allowance was spent first
        // Front-runner can use old + new allowance
        
        emit Approval(msg.sender, spender, amount);
    }
    
    /**
     * @dev Spend via transferFrom
     * Works with the buggy approve above
     */
    function spendAllowance(address token, address from, address to, uint256 amount) external {
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        allowances[from][msg.sender] -= amount;
        
        // BUG #8: Return value not checked
        IERC20(token).transferFrom(from, to, amount);
    }

    // ========== VULNERABILITY #3: FEE-ON-TRANSFER ==========
    
    /**
     * @dev Deposit tokens into vault
     * BUG #3: Assumes received amount == sent amount
     * Fee-on-transfer tokens (USDT, PAXG, etc.) take a fee during transfer
     * Contract credits user for 100 but only receives 98
     * 
     * Attack: Deposit 100 FOT tokens (2% fee) â†’ credited 100, contract got 98
     * Withdraw 100 â†’ contract sends 100 but only had 98 â†’ insolvency
     */
    function depositToken(address token, uint256 amount) external {
        require(supportedTokens[token], "Token not supported");
        
        // BUG #3: Credits full amount without checking actual received
        // Should use: balanceBefore = token.balanceOf(this); transfer; balanceAfter - balanceBefore
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        // BUG #3: Credits the SENT amount, not the RECEIVED amount
        userDeposits[token][msg.sender] += amount;
        totalTokenDeposits[token] += amount;
        
        // Over time, totalTokenDeposits > actual balance â†’ insolvency
        
        emit Deposit(token, msg.sender, amount);
    }
    
    /**
     * @dev Withdraw tokens
     * BUG #3b: Sends full credited amount, but balance is less
     */
    function withdrawToken(address token, uint256 amount) external {
        require(userDeposits[token][msg.sender] >= amount, "Insufficient");
        
        userDeposits[token][msg.sender] -= amount;
        totalTokenDeposits[token] -= amount;
        
        // BUG #3b: May fail or drain more than available
        // BUG #8: Return value not checked
        IERC20(token).transfer(msg.sender, amount);
        
        emit Withdrawal(token, msg.sender, amount);
    }

    // ========== VULNERABILITY #4: REBASING TOKEN DESYNC ==========
    
    /**
     * @dev Deposit rebasing token (AMPL, stETH, etc.)
     * BUG #4: Balance changes between operations without any transfer
     * Rebasing tokens automatically adjust balances (up or down)
     * 
     * Attack with positive rebase:
     *   Deposit 100 AMPL â†’ credited 100. AMPL rebases +10%.
     *   Contract now holds 110 AMPL but only tracks 100.
     *   Someone else can claim the extra 10 AMPL.
     * 
     * Attack with negative rebase:
     *   Deposit 100 AMPL â†’ credited 100. AMPL rebases -50%.
     *   Contract now holds 50 AMPL but tracks 100.
     *   First withdrawer gets 50, second gets nothing â†’ bank run.
     */
    function depositRebasingToken(address token, uint256 amount) external {
        require(supportedTokens[token], "Not supported");
        
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        // BUG #4: Stores absolute amount, but rebasing token may change balance
        // Should store shares (amount * totalShares / totalBalance) instead
        userDeposits[token][msg.sender] += amount;
        
        // Snapshot current balance â€” but this goes stale on rebase!
        lastKnownBalance[token] = IERC20(token).balanceOf(address(this));
    }
    
    /**
     * @dev Check for rebase â€” reveals the desync
     * BUG #4b: Gap between tracked and actual = exploitable
     */
    function getRebaseGap(address token) external view returns (int256) {
        uint256 actual = IERC20(token).balanceOf(address(this));
        uint256 tracked = totalTokenDeposits[token];
        // Positive = rebase up (free money available)
        // Negative = rebase down (insolvency)
        return int256(actual) - int256(tracked);
    }
    
    /**
     * @dev Claim rebase surplus â€” anyone can call!
     * BUG #4c: Surplus from positive rebase is claimable by anyone
     */
    function claimRebaseSurplus(address token) external {
        uint256 actual = IERC20(token).balanceOf(address(this));
        uint256 tracked = totalTokenDeposits[token];
        
        if (actual > tracked) {
            uint256 surplus = actual - tracked;
            // BUG #4c: No access control â€” anyone can drain rebase surplus
            // Should go to depositors proportionally
            IERC20(token).transfer(msg.sender, surplus);
        }
    }

    // ========== VULNERABILITY #5: TOKEN CALLBACK HOOKS ==========
    
    /**
     * @dev Receive ERC-777-like tokens with callback
     * BUG #5: Token with transfer hooks enables reentrancy
     * 
     * Attack: ERC-777 token calls tokensReceived() on recipient
     * During callback, reenter deposit/withdraw before state update
     * Classic reentrancy via token hooks, not raw ETH calls
     */
    function depositWithCallback(address token, uint256 amount) external {
        // State update AFTER external call â€” classic reentrancy
        // For ERC-777: transferFrom triggers tokensReceived() on this contract
        // During that callback, balances are not yet updated
        
        // BUG #5: External call before state update
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        // State updated AFTER the transfer (which includes callback)
        // Reentrant call during token hook sees old state
        userDeposits[token][msg.sender] += amount;
        totalTokenDeposits[token] += amount;
    }
    
    /**
     * @dev ERC-777 token received callback
     * BUG #5b: This callback can be exploited for reentrancy
     */
    function tokensReceived(
        address /* operator */,
        address from,
        address /* to */,
        uint256 amount,
        bytes calldata /* userData */,
        bytes calldata /* operatorData */
    ) external {
        // BUG #5b: During this callback, the deposit state hasn't been updated yet
        // Attacker can call withdraw() or other functions with stale state
        
        // Auto-compound: deposit the received tokens too
        // This creates a nested deposit during an ongoing deposit!
        userDeposits[msg.sender][from] += amount;
    }

    // ========== VULNERABILITY #6: INFINITE APPROVAL CHAIN ==========
    
    /**
     * @dev One-click max approval for convenience
     * BUG #6: type(uint256).max approval = permanent unlimited access
     * If approved contract gets exploited, attacker can drain everything
     * 
     * Attack chain: User approves Router for MAX â†’ Router has bug â†’
     * Attacker uses Router to transferFrom(user, attacker, user.balance)
     */
    function approveMax(address token, address spender) external {
        // BUG #6: Infinite approval â€” never decreases, never expires
        // If spender contract is compromised, user loses all tokens
        IERC20(token).approve(spender, type(uint256).max);
        
        // No expiry, no cap, no revocation mechanism
    }
    
    /**
     * @dev Permit-based approval (EIP-2612) 
     * BUG #6b: Permit + transferFrom = gasless drain
     * Attacker with valid signature can approve + transfer in 1 tx
     */
    function permitAndTransfer(
        address token,
        address from,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // BUG #6b: Uses permit to set approval, then immediately transfers
        // If signature is leaked/phished, instant drain with no on-chain approval tx
        IERC20Permit(token).permit(from, address(this), amount, deadline, v, r, s);
        
        // Immediately use the approval
        IERC20(token).transferFrom(from, msg.sender, amount);
    }

    // ========== VULNERABILITY #7: GOVERNANCE FLASH LOAN ==========
    
    /**
     * @dev Deposit tokens for voting power
     * BUG #7: No snapshot at proposal creation time
     * Flash loan â†’ deposit â†’ vote â†’ withdraw â†’ return in 1 tx
     * 
     * REAL: Beanstalk $182M exploit used this exact pattern
     */
    function depositForVoting(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        // BUG #7: Voting power updated immediately, no timelock/snapshot
        // Flash loan tokens â†’ instant voting power â†’ vote â†’ withdraw â†’ return
        votingPower[msg.sender] += amount;
    }
    
    function withdrawVoting(address token, uint256 amount) external {
        require(votingPower[msg.sender] >= amount, "Insufficient power");
        
        votingPower[msg.sender] -= amount;
        IERC20(token).transfer(msg.sender, amount);
    }
    
    /**
     * @dev Vote on proposal
     * BUG #7b: Flash-loaned voting power accepted
     */
    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.number <= p.endBlock, "Voting ended");
        require(!p.hasVoted[msg.sender], "Already voted");
        
        p.hasVoted[msg.sender] = true;
        
        // BUG #7b: Uses current votingPower, not snapshot at proposal creation
        // Flash loan tokens in same block â†’ votingPower is inflated
        if (support) {
            p.forVotes += votingPower[msg.sender];
        } else {
            p.againstVotes += votingPower[msg.sender];
        }
    }
    
    /**
     * @dev Execute proposal
     * BUG #7c: Can be executed in same tx as vote if quorum = 0
     */
    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.number > p.endBlock, "Voting not ended");
        require(!p.executed, "Already executed");
        require(p.forVotes >= quorum, "Quorum not reached");
        require(p.forVotes > p.againstVotes, "Not approved");
        
        p.executed = true;
        
        // BUG: Arbitrary call from governance
        (bool success, ) = p.target.call(p.callData);
        require(success, "Execution failed");
    }
    
    /**
     * @dev Create proposal â€” no minimum voting power required
     * BUG #7d: Anyone can create proposals, no proposer threshold
     */
    function createProposal(
        string calldata description,
        address target,
        bytes calldata callData,
        uint256 votingPeriod
    ) external returns (uint256) {
        uint256 id = proposalCount++;
        Proposal storage p = proposals[id];
        p.description = description;
        p.target = target;
        p.callData = callData;
        p.endBlock = block.number + votingPeriod;
        
        return id;
    }
    // ========== VULNERABILITY #8: RETURN VALUE HANDLING ==========
    
    /**
     * @dev Batch transfer using low-level call
     * BUG #8: Non-standard ERC-20 tokens don't return bool
     * USDT's transfer() returns void â†’ call returns true but no data
     * If we check return data, USDT transfers always "fail"
     * If we don't check, failed transfers silently succeed
     */
    function batchTransferUnsafe(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        require(recipients.length == amounts.length, "Length mismatch");
        
        for (uint i = 0; i < recipients.length; i++) {
            // BUG #8: Low-level call â€” different tokens return different things
            // Standard ERC-20: returns (bool true)
            // USDT: returns nothing (void)
            // BNB: returns (bool) but non-standard selector
            bytes memory data = abi.encodeWithSelector(
                IERC20.transfer.selector,
                recipients[i],
                amounts[i]
            );
            
            (bool success, bytes memory returnData) = token.call(data);
            
            // BUG #8: This check fails for USDT (empty returnData)
            // Should use: success && (returnData.length == 0 || abi.decode(returnData, (bool)))
            require(success && abi.decode(returnData, (bool)), "Transfer failed");
        }
    }

    // ========== VULNERABILITY #9: PERMIT + TRANSFERFROM RACE ==========
    
    /**
     * @dev Double-spend via permit race
     * BUG #9: Victim signs permit for spender A. Attacker front-runs:
     * 1. submits permit (setting approval to X)
     * 2. calls transferFrom for X (draining X)
     * 3. victim's original tx with new permit also sets approval to X
     * 4. attacker calls transferFrom again for X
     * Total: 2X drained instead of X
     */
    function permitThenSpend(
        address token,
        address from,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // BUG #9: Permit sets approval, but old approval might not be spent
        // If front-runner calls with same permit, double-spend is possible
        IERC20Permit(token).permit(from, msg.sender, amount, deadline, v, r, s);
        
        // BUG #9: No check that previous allowance was 0
        IERC20(token).transferFrom(from, address(this), amount);
    }

    // ========== VULNERABILITY #10: DONATION ATTACK ==========
    
    /**
     * @dev Share-based deposit into vault
     * BUG #10: First depositor gets 1 share, then donates tokens directly
     * Second depositor gets 0 shares due to rounding
     * 
     *  ðŸ”— CHAIN: Same as PrecisionVault share inflation
     * Attack:
     *   1. Deposit 1 wei â†’ 1 share
     *   2. Donate 1M tokens directly (transfer, not deposit)
     *   3. Now 1 share = 1M+1 tokens
     *   4. Victim deposits 999K â†’ gets 0 shares (999K * 1 / 1M+1 = 0)
     *   5. Attacker withdraws 1 share â†’ gets 1M + 999K + 1 tokens
     */
    function depositForShares(address token, uint256 amount) external {
        uint256 shares;
        uint256 balance = IERC20(token).balanceOf(address(this));
        uint256 supply = totalShares[token];
        
        if (supply == 0) {
            // BUG #10: First depositor â€” 1:1 ratio, no minimum
            shares = amount;
        } else {
            // BUG #10: Uses actual balance (includes donations)
            // attacker donation inflates balance â†’ new depositor gets 0 shares
            shares = (amount * supply) / balance;
        }
        
        // BUG #10: No minimum shares check â€” 0 shares is valid!
        require(shares > 0 || amount == 0, "Zero shares"); // The || amount==0 weakens the check
        
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        userShares[token][msg.sender] += shares;
        totalShares[token] += shares;
    }
    
    function withdrawShares(address token, uint256 shares) external {
        require(userShares[token][msg.sender] >= shares, "Insufficient shares");
        
        uint256 balance = IERC20(token).balanceOf(address(this));
        uint256 supply = totalShares[token];
        
        uint256 amount = (shares * balance) / supply;
        
        userShares[token][msg.sender] -= shares;
        totalShares[token] -= shares;
        
        IERC20(token).transfer(msg.sender, amount);
    }

    // ========== COMBO: FLASH LOAN GOVERNANCE ATTACK ==========
    
    /**
     * @dev Full flash loan governance exploit in one function
     * ðŸ”— CHAIN: FlashLoanVictim â†’ TokenPoisoning governance
     * 
     * BUG COMBO: Flash loan + no snapshot + same-block execution
     * Beanstalk-style attack vector
     */
    function flashGovernanceAttack(
        uint256 flashAmount,
        uint256 proposalId
    ) external {
        // Step 1: Flash loan tokens
        if (address(flashLoanVictim) != address(0)) {
            flashLoanVictim.flashLoan(flashAmount);
        }
        
        // Step 2: Deposit for instant voting power (BUG #7)
        votingPower[msg.sender] += flashAmount;
        
        // Step 3: Vote with flash-loaned power (BUG #7b)
        Proposal storage p = proposals[proposalId];
        if (!p.hasVoted[msg.sender]) {
            p.hasVoted[msg.sender] = true;
            p.forVotes += votingPower[msg.sender];
        }
        
        // Step 4: Remove voting power and return flash loan
        votingPower[msg.sender] -= flashAmount;
        
        // Votes are already counted â€” flash loan can be returned
    }

    // ========== VAULT DONATION ATTACK VIA PRECISION VAULT ==========
    
    /**
     * @dev Exploit PrecisionVault share inflation
     * ðŸ”— CHAIN: PrecisionVault â†’ TokenPoisoning
     * 
     * Uses existing vault's donation vulnerability to steal deposits
     */
    function exploitVaultDonation(address token, uint256 donationAmount) external {
        require(address(precisionVault) != address(0), "Vault not set");
        
        // Step 1: Be first depositor in vault (1 share for 1 wei)
        IERC20(token).approve(address(precisionVault), 1);
        precisionVault.deposit(1);
        
        // Step 2: Donate tokens directly to vault (bypass deposit accounting)
        // BUG: Vault uses balanceOf for withdraw but totalDeposited for deposit
        IERC20(token).transfer(address(precisionVault), donationAmount);
        
        // Step 3: Now virtualPrice >> actualPrice
        // Next depositor gets 0 shares â†’ their tokens are trapped
    }

    receive() external payable {}
}

/**
 * @title MaliciousERC777
 * @dev Demonstrates token callback reentrancy attack
 */
contract MaliciousERC777 {
    TokenPoisoning public target;
    uint256 public attackCount;
    
    constructor(address payable _target) {
        target = TokenPoisoning(_target);
    }
    
    /**
     * @dev ERC-777 tokensReceived callback
     * Called during transfer â†’ reenters deposit before state update
     */
    function tokensReceived(
        address,
        address,
        address,
        uint256 amount,
        bytes calldata,
        bytes calldata
    ) external {
        // Reenter during token transfer callback
        if (attackCount < 3) {
            attackCount++;
            // BUG: Target's depositWithCallback hasn't updated state yet
            // This reentrant call credits us again with stale balances
            target.depositWithCallback(msg.sender, amount);
        }
    }
}

/**
 * @title FeeOnTransferToken
 * @dev Simulates a fee-on-transfer token for testing
 */
contract FeeOnTransferToken {
    string public name = "Fee Token";
    string public symbol = "FEE";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public feePercent = 2; // 2% fee on every transfer
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * feePercent) / 100;
        uint256 received = amount - fee;
        
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += received; // Recipient gets less!
        balanceOf[address(0)] += fee; // Fee burned
        
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        
        uint256 fee = (amount * feePercent) / 100;
        uint256 received = amount - fee;
        
        balanceOf[from] -= amount;
        balanceOf[to] += received;
        balanceOf[address(0)] += fee;
        
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
