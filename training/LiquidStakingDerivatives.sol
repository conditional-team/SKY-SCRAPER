// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LiquidStakingDerivatives
 * @dev Training Contract #47 - Liquid Staking Derivative Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Depeg Cascade via Withdrawal Queue (LSD-DEPEG-01)
 * 2. Rebasing Accounting Error (LSD-REBASE-01)
 * 3. Oracle Lag on Staking Ratio (LSD-ORACLE-01)
 * 4. Slashing Propagation Delay (LSD-SLASH-01)
 * 5. Validator Exit Front-run (LSD-EXIT-01)
 * 6. Withdrawal NFT Manipulation (LSD-WNFT-01)
 * 7. Share Price Inflation Attack (LSD-INFLATE-01)
 * 8. Unbonding Period Arbitrage (LSD-UNBOND-01)
 * 9. Rewards Sandwich (LSD-REWARD-01)
 * 10. Operator Fee Manipulation (LSD-OPFEE-01)
 * 11. DVT Key Theft (LSD-DVT-01)
 * 12. MEV Boost Theft via Proposer (LSD-MEV-01)
 * 13. stETH/wstETH Conversion Rounding (LSD-ROUND-01)
 * 14. EigenLayer Restaking Double-Count (LSD-RESTAKE-01)
 * 15. Queue Jump via Priority Fee (LSD-QJUMP-01)
 * 16. Deposit Front-run for Shares (LSD-DEPOSIT-01)
 * 17. Negative Rebase Socialization (LSD-NEGREB-01)
 * 18. Cross-LSD Arbitrage Oracle (LSD-XARB-01)
 * 19. Validator Registry Poisoning (LSD-VREG-01)
 * 20. Emergency Withdrawal Drain (LSD-EMERGENCY-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): LSD-*, share inflation, rounding
 * - Engine 2 (deep-semantic): rebase logic, withdrawal queue
 * - Engine 3 (state-desync): oracle lag, slashing propagation
 * - Engine 13 (mev-analyzer): sandwich, front-run, arbitrage
 */

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

// ========== VULN 1: Depeg Cascade via Withdrawal Queue (LSD-DEPEG-01) ==========

contract LiquidStakingVault {
    IERC20 public stakingToken; // ETH wrapper
    uint256 public totalDeposited;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    
    // Withdrawal queue
    struct WithdrawalRequest {
        address requester;
        uint256 shareAmount;
        uint256 timestamp;
        bool fulfilled;
    }
    WithdrawalRequest[] public withdrawalQueue;
    uint256 public queueHead;
    uint256 public totalPendingWithdrawals;

    uint256 public exchangeRate = 1e18; // stToken:ETH ratio
    address public oracle;
    address public owner;
    
    // Operator / validator config
    mapping(address => bool) public operators;
    mapping(bytes32 => uint256) public validatorBalances;
    uint256 public operatorFee = 500; // 5%
    uint256 public totalRewards;
    
    // Slashing
    uint256 public lastSlashingCheck;
    uint256 public pendingSlashAmount;
    bool public slashingApplied;

    constructor(address _token, address _oracle) {
        stakingToken = IERC20(_token);
        oracle = _oracle;
        owner = msg.sender;
    }

    // BUG #1: withdrawal queue has no max capacity => bank-run causes depeg
    // When queue grows, secondary market panics => stToken trades below peg
    function requestWithdrawal(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient shares");
        shares[msg.sender] -= shareAmount;
        // VULN: no cap on queue length, no cooldown, enables bank-run cascade
        withdrawalQueue.push(WithdrawalRequest({
            requester: msg.sender,
            shareAmount: shareAmount,
            timestamp: block.timestamp,
            fulfilled: false
        }));
        totalPendingWithdrawals += shareAmount;
        totalShares -= shareAmount;
    }

    // ========== VULN 2: Rebasing Accounting Error (LSD-REBASE-01) ==========

    // BUG #2: rebase updates totalDeposited but shares are already burned from queue
    // causing per-share value to jump, benefiting remaining holders unfairly
    function rebase(uint256 newTotalDeposited) external {
        require(msg.sender == oracle, "only oracle");
        // VULN: totalShares was reduced by pending withdrawals, but ETH isn't out yet
        // remaining shares get inflated value: newTotal / (total - pending)
        totalDeposited = newTotalDeposited;
        exchangeRate = (totalDeposited * 1e18) / totalShares; // inflated!
    }

    // ========== VULN 3: Oracle Lag on Staking Ratio (LSD-ORACLE-01) ==========

    // BUG #3: exchange rate only updates on rebase(), stale between updates
    // attacker deposits when rate is stale-low, withdraws after rebase
    function deposit(uint256 amount) external returns (uint256 sharesOut) {
        stakingToken.transferFrom(msg.sender, address(this), amount);
        // VULN: exchangeRate may be hours old, enabling timing arbitrage
        sharesOut = (amount * 1e18) / exchangeRate;
        shares[msg.sender] += sharesOut;
        totalShares += sharesOut;
        totalDeposited += amount;
    }

    // ========== VULN 4: Slashing Propagation Delay (LSD-SLASH-01) ==========

    // BUG #4: slashing event detected off-chain but takes 1+ epoch to propagate
    // attacker withdraws before slashing is applied on-chain
    function reportSlashing(uint256 slashedAmount) external {
        require(msg.sender == oracle, "only oracle");
        // VULN: slash stored as pending, not immediately applied
        pendingSlashAmount += slashedAmount;
        lastSlashingCheck = block.timestamp;
        // Attacker front-runs this by withdrawing with pre-slash exchange rate
    }

    function applySlashing() external {
        require(pendingSlashAmount > 0, "no slash");
        // Applied later—window between report and apply is exploitable
        totalDeposited -= pendingSlashAmount;
        exchangeRate = (totalDeposited * 1e18) / totalShares;
        pendingSlashAmount = 0;
        slashingApplied = true;
    }

    // ========== VULN 5: Validator Exit Front-run (LSD-EXIT-01) ==========

    // BUG #5: validator exit triggers large ETH return, attacker deposits just before
    // to capture disproportionate share of the returned ETH
    function processValidatorExit(bytes32 validatorId) external {
        require(msg.sender == owner, "only owner");
        uint256 exitedAmount = validatorBalances[validatorId];
        // VULN: totalDeposited increases, but anyone who deposited 1 block before
        // gets shares at old exchange rate, capturing exit rewards
        totalDeposited += exitedAmount;
        validatorBalances[validatorId] = 0;
        exchangeRate = (totalDeposited * 1e18) / totalShares;
    }

    // ========== VULN 6: Withdrawal NFT Manipulation (LSD-WNFT-01) ==========

    // BUG #6: withdrawal request index is predictable and transferable
    // attacker can monitor queue and snipe profitable positions
    function transferWithdrawalRequest(uint256 index, address newOwner) external {
        require(withdrawalQueue[index].requester == msg.sender, "not owner");
        // VULN: no check that request hasn't been partially processed
        // secondary market for withdrawal NFTs enables front-running fulfillment
        withdrawalQueue[index].requester = newOwner;
    }

    // ========== VULN 7: Share Price Inflation Attack (LSD-INFLATE-01) ==========

    // BUG #7: first depositor can inflate share price by donating to vault
    function inflateSharePrice() external payable {
        // VULN: direct transfer to vault increases totalDeposited
        // if totalShares == 1, each share becomes worth huge amount
        // subsequent depositors get 0 shares due to rounding
        totalDeposited += msg.value;
        if (totalShares > 0) {
            exchangeRate = (totalDeposited * 1e18) / totalShares;
        }
    }

    // ========== VULN 8: Unbonding Period Arbitrage (LSD-UNBOND-01) ==========

    uint256 public constant UNBOND_PERIOD = 7 days;

    // BUG #8: unbonding period creates arb window—stToken trades at discount
    // during high unbonding demand, attacker buys discounted stToken on DEX
    // then redeems at full value when queue clears
    function fulfillWithdrawals(uint256 count) external {
        for (uint256 i = 0; i < count && queueHead < withdrawalQueue.length; i++) {
            WithdrawalRequest storage req = withdrawalQueue[queueHead];
            // VULN: no FIFO enforcement with time check
            // early requesters may get delayed while late requesters with higher gas get processed
            if (block.timestamp >= req.timestamp + UNBOND_PERIOD && !req.fulfilled) {
                uint256 ethAmount = (req.shareAmount * exchangeRate) / 1e18;
                req.fulfilled = true;
                totalPendingWithdrawals -= req.shareAmount;
                stakingToken.transfer(req.requester, ethAmount);
            }
            queueHead++;
        }
    }

    // ========== VULN 9: Rewards Sandwich (LSD-REWARD-01) ==========

    // BUG #9: reward distribution is MEV-sandwichable
    // attacker deposits before distributeRewards(), withdraws after
    function distributeRewards(uint256 rewardAmount) external {
        require(msg.sender == oracle, "only oracle");
        // VULN: rewards added to totalDeposited => exchange rate jumps
        // sandwich: deposit (get shares at old rate) → distributeRewards → withdraw (at new rate)
        totalDeposited += rewardAmount;
        totalRewards += rewardAmount;
        exchangeRate = (totalDeposited * 1e18) / totalShares;
    }

    // ========== VULN 10: Operator Fee Manipulation (LSD-OPFEE-01) ==========

    // BUG #10: operator can change fee right before rewards distribution
    // capturing outsized portion of staking rewards
    function setOperatorFee(uint256 newFee) external {
        require(operators[msg.sender], "not operator");
        // VULN: no timelock, no max cap, operator can set 100% fee
        operatorFee = newFee;
    }

    function collectOperatorFees() external {
        require(operators[msg.sender], "not operator");
        uint256 fee = (totalRewards * operatorFee) / 10000;
        totalRewards = 0;
        totalDeposited -= fee;
        stakingToken.transfer(msg.sender, fee);
    }

    // ========== VULN 11: DVT Key Theft (LSD-DVT-01) ==========

    mapping(bytes32 => bytes) public validatorKeys;

    // BUG #11: validator key registration allows overwrite without ownership proof
    function registerValidator(bytes32 validatorId, bytes calldata pubkey) external {
        require(operators[msg.sender], "not operator");
        // VULN: any operator can overwrite any validator's key => funds theft
        validatorKeys[validatorId] = pubkey;
        validatorBalances[validatorId] = 32 ether;
    }

    // ========== VULN 12: MEV Boost Theft via Proposer (LSD-MEV-01) ==========

    mapping(address => uint256) public mevRewards;

    // BUG #12: proposer keeps MEV rewards that should be socialized to stakers
    function receiveMEVReward() external payable {
        // VULN: reward credited to msg.sender (proposer), not to vault
        mevRewards[msg.sender] += msg.value;
        // Should add to totalDeposited for all stakers
    }

    // ========== VULN 13: stETH/wstETH Conversion Rounding (LSD-ROUND-01) ==========

    mapping(address => uint256) public wrappedBalances;

    // BUG #13: wrap/unwrap has rounding error that loses 1 wei per operation
    // attacker loops wrap/unwrap to drain dust over millions of txs
    function wrap(uint256 stEthAmount) external returns (uint256 wstEthAmount) {
        // VULN: integer division rounds down, 1 wei lost each wrap
        wstEthAmount = (stEthAmount * 1e18) / exchangeRate;
        shares[msg.sender] -= stEthAmount;
        wrappedBalances[msg.sender] += wstEthAmount;
    }

    function unwrap(uint256 wstEthAmount) external returns (uint256 stEthAmount) {
        // VULN: reverse conversion also rounds down—attacker picks profitable direction
        stEthAmount = (wstEthAmount * exchangeRate) / 1e18;
        wrappedBalances[msg.sender] -= wstEthAmount;
        shares[msg.sender] += stEthAmount;
    }

    // ========== VULN 14: EigenLayer Restaking Double-Count (LSD-RESTAKE-01) ==========

    mapping(address => uint256) public restaked;

    // BUG #14: restaked ETH counted in both LSD vault AND EigenLayer
    // inflating total backing and enabling over-borrowing on lending protocols
    function restake(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        // VULN: shares still counted in totalShares AND restaked
        // effectively double-counted collateral
        restaked[msg.sender] += amount;
        // Should reduce totalShares or lock shares
    }

    // ========== VULN 15: Queue Jump via Priority Fee (LSD-QJUMP-01) ==========

    // BUG #15: fulfillWithdrawals processes in array order, but MEV bots
    // can reorder withdrawal requests to prioritize own position
    function priorityWithdraw(uint256 shareAmount) external payable {
        require(shares[msg.sender] >= shareAmount, "insufficient");
        shares[msg.sender] -= shareAmount;
        // VULN: MEV opportunity—higher gas price = earlier processing
        // violates fairness of withdrawal queue
        withdrawalQueue.push(WithdrawalRequest({
            requester: msg.sender,
            shareAmount: shareAmount,
            timestamp: block.timestamp,
            fulfilled: false
        }));
        totalPendingWithdrawals += shareAmount;
        totalShares -= shareAmount;
    }

    // ========== VULN 16: Deposit Front-run for Shares (LSD-DEPOSIT-01) ==========

    // BUG #16: attacker monitors mempool for large deposits
    // front-runs to deposit first, pushing exchange rate up
    // then back-runs victim's deposit to extract value
    // (this is inherent to the deposit() function above using stale exchangeRate)

    // ========== VULN 17: Negative Rebase Socialization (LSD-NEGREB-01) ==========

    // BUG #17: when a negative rebase occurs (slashing), new depositors
    // who entered after the slashing event but before rebase()
    // get their shares diluted retroactively
    function negativeRebase(uint256 lossAmount) external {
        require(msg.sender == oracle);
        // VULN: users who deposited in gap between event and rebase
        // lose funds they never should have been exposed to
        totalDeposited -= lossAmount;
        exchangeRate = (totalDeposited * 1e18) / totalShares;
    }

    // ========== VULN 18: Cross-LSD Arbitrage Oracle (LSD-XARB-01) ==========

    mapping(address => uint256) public otherLSDRates;

    // BUG #18: oracle provides rates for multiple LSDs
    // attacker exploits rate difference between rETH, stETH, cbETH
    function updateCrossRate(address otherLSD, uint256 rate) external {
        require(msg.sender == oracle);
        // VULN: no staleness check, cross-LSD arb if rates update at different times
        otherLSDRates[otherLSD] = rate;
    }

    // ========== VULN 19: Validator Registry Poisoning (LSD-VREG-01) ==========

    // BUG #19: malicious operator registers validators with exit credentials
    // pointing to attacker address, not the vault
    function registerValidatorBatch(bytes32[] calldata ids, bytes[] calldata pubkeys) external {
        require(operators[msg.sender], "not operator");
        for (uint256 i = 0; i < ids.length; i++) {
            // VULN: withdrawal credentials in pubkey not validated
            // operator can set own address as withdrawal destination
            validatorKeys[ids[i]] = pubkeys[i];
            validatorBalances[ids[i]] = 32 ether;
        }
    }

    // ========== VULN 20: Emergency Withdrawal Drain (LSD-EMERGENCY-01) ==========

    bool public emergencyMode;

    // BUG #20: emergency mode allows instant withdrawal at stale exchange rate
    // race condition: attacker triggers emergency + withdraws in same block
    function setEmergency(bool _emergency) external {
        require(msg.sender == owner);
        emergencyMode = _emergency;
    }

    function emergencyWithdraw() external {
        require(emergencyMode, "not emergency");
        uint256 userShares = shares[msg.sender];
        require(userShares > 0, "no shares");
        shares[msg.sender] = 0;
        // VULN: uses potentially stale/manipulated exchange rate
        // no slippage protection in emergency mode
        uint256 ethAmount = (userShares * exchangeRate) / 1e18;
        totalShares -= userShares;
        totalDeposited -= ethAmount;
        stakingToken.transfer(msg.sender, ethAmount);
    }

    // Helper
    function addOperator(address op) external {
        require(msg.sender == owner);
        operators[op] = true;
    }

    receive() external payable {
        totalDeposited += msg.value;
    }
}
