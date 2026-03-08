// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title YieldAggregator
 * @dev Training Contract #56 - Yield Aggregator & Strategy Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Strategy Migration Drain (YIELD-MIGRATE-01)
 * 2. Harvest Sandwich (YIELD-HARVEST-01)
 * 3. Vault Share Accounting Error (YIELD-SHARE-01)
 * 4. Strategy Profit Reporting Lie (YIELD-REPORT-01)
 * 5. Emergency Withdrawal Skim (YIELD-EMERGENCY-01)
 * 6. Debt Ratio Manipulation (YIELD-DEBTRATIO-01)
 * 7. Flash Deposit-Harvest-Withdraw (YIELD-FLASH-01)
 * 8. Strategy Loss Hiding (YIELD-LOSSHIDE-01)
 * 9. Reward Token Swap Front-run (YIELD-REWARDSWAP-01)
 * 10. Management Fee Extraction (YIELD-MGMTFEE-01)
 * 11. Performance Fee on Unrealized (YIELD-PERFFEE-01)
 * 12. Locked Profit Manipulation (YIELD-LOCKEDPROF-01)
 * 13. Deposit Limit Bypass (YIELD-DEPOSITLIM-01)
 * 14. Strategy Queue Ordering Attack (YIELD-QUEUE-01)
 * 15. Harvest Timing Manipulation (YIELD-TIMING-01)
 * 16. Total Assets Desync (YIELD-DESYNC-01)
 * 17. Withdrawal Fee Avoidance (YIELD-WFEE-01)
 * 18. Underlying Protocol Exploit Pass-through (YIELD-PASSTHRU-01)
 * 19. Vault Token Rebasing (YIELD-VAULTREBASE-01)
 * 20. Auto-Compound Slippage (YIELD-AUTOCOMP-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): YIELD-*, vault, harvest, strategy
 * - Engine 2 (deep-semantic): share accounting, profit calculation
 * - Engine 3 (state-desync): total assets, debt ratio
 * - Engine 13 (mev-analyzer): sandwich, front-run, flash
 */

interface IERC20Yield {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface ISwapRouter {
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256);
}

contract YieldVault {
    IERC20Yield public want;  // underlying token
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    
    // Strategy management
    struct Strategy {
        address strategyAddress;
        uint256 debtRatio;     // % of vault assets allocated (basis points)
        uint256 totalDebt;     // current debt from vault
        uint256 totalGain;
        uint256 totalLoss;
        uint256 lastReport;
        bool active;
    }
    
    mapping(address => Strategy) public strategies;
    address[] public withdrawalQueue;
    uint256 public totalDebt;
    uint256 public totalStrategyDebt;
    
    // Fees
    uint256 public managementFee = 200;    // 2% annual
    uint256 public performanceFee = 2000;  // 20% of profit
    uint256 public withdrawalFee = 50;     // 0.5%
    address public feeRecipient;
    
    // Profit
    uint256 public lockedProfit;
    uint256 public lockedProfitDegradation;
    uint256 public lastReport;
    
    // Limits
    uint256 public depositLimit = type(uint256).max;
    uint256 public totalAssetsCached;
    
    address public governance;
    ISwapRouter public router;
    IERC20Yield public rewardToken;

    constructor(address _want, address _router, address _reward) {
        want = IERC20Yield(_want);
        router = ISwapRouter(_router);
        rewardToken = IERC20Yield(_reward);
        governance = msg.sender;
        feeRecipient = msg.sender;
        lockedProfitDegradation = 6 hours;
    }

    // ========== VULN 1: Strategy Migration Drain (YIELD-MIGRATE-01) ==========

    // BUG #1: during strategy migration, tokens briefly in vault
    // attacker deposits during migration, captures migrated tokens as share value
    function migrateStrategy(address oldStrategy, address newStrategy) external {
        require(msg.sender == governance, "not gov");
        Strategy storage old = strategies[oldStrategy];
        uint256 migratedAmount = old.totalDebt;
        
        // Pull all tokens from old strategy to vault
        (bool ok, ) = oldStrategy.call(abi.encodeWithSignature("withdraw(uint256)", migratedAmount));
        require(ok);
        
        // VULN: tokens sit in vault between these two calls
        // deposit/withdraw in this window captures migrated value
        // totalAssets() suddenly includes migrated tokens = inflated share price
        
        // Push to new strategy
        want.transfer(newStrategy, migratedAmount);
        strategies[newStrategy] = Strategy({
            strategyAddress: newStrategy,
            debtRatio: old.debtRatio,
            totalDebt: migratedAmount,
            totalGain: 0,
            totalLoss: 0,
            lastReport: block.timestamp,
            active: true
        });
        old.active = false;
        old.totalDebt = 0;
    }

    // ========== VULN 2: Harvest Sandwich (YIELD-HARVEST-01) ==========

    // BUG #2: harvest reports profit => share price increases
    // MEV bot deposits before harvest, withdraws after
    function harvest(address strategy) external {
        Strategy storage s = strategies[strategy];
        require(s.active, "inactive");
        
        uint256 balanceBefore = want.balanceOf(address(this));
        (bool ok, ) = strategy.call(abi.encodeWithSignature("harvest()"));
        require(ok);
        uint256 balanceAfter = want.balanceOf(address(this));
        
        // VULN: profit immediately reflected in totalAssets
        // sandwicher: deposit → harvest → withdraw = risk-free profit
        uint256 profit = balanceAfter > balanceBefore ? balanceAfter - balanceBefore : 0;
        s.totalGain += profit;
        
        // Performance fee
        uint256 fee = profit * performanceFee / 10000;
        if (fee > 0) {
            uint256 feeShares = fee * totalShares / _totalAssets();
            shares[feeRecipient] += feeShares;
            totalShares += feeShares;
        }
        
        lockedProfit = profit - fee;
        lastReport = block.timestamp;
    }

    // ========== VULN 3: Vault Share Accounting Error (YIELD-SHARE-01) ==========

    // BUG #3: first depositor 1 wei attack
    function deposit(uint256 amount) external returns (uint256 sharesOut) {
        require(amount > 0, "zero");
        require(_totalAssets() + amount <= depositLimit, "limit");
        
        want.transferFrom(msg.sender, address(this), amount);
        
        if (totalShares == 0) {
            sharesOut = amount;
        } else {
            // VULN: if totalShares == 1 and totalAssets() is huge (via donation)
            // sharesOut rounds to 0, depositor gets nothing
            sharesOut = amount * totalShares / _totalAssets();
        }
        
        require(sharesOut > 0, "zero shares");
        shares[msg.sender] += sharesOut;
        totalShares += sharesOut;
    }

    // ========== VULN 4: Strategy Profit Reporting Lie (YIELD-REPORT-01) ==========

    // BUG #4: strategy can lie about profit/loss
    function report(uint256 gain, uint256 loss) external {
        Strategy storage s = strategies[msg.sender];
        require(s.active, "not strategy");
        // VULN: no verification that gain is real
        // strategy can report fake gains to inflate share price
        // then governance can withdraw premium before loss materialized
        s.totalGain += gain;
        s.totalLoss += loss;
        s.lastReport = block.timestamp;
        totalStrategyDebt = totalStrategyDebt + gain - loss;
    }

    // ========== VULN 5: Emergency Withdrawal Skim (YIELD-EMERGENCY-01) ==========

    // BUG #5: emergency withdrawal uses stale exchange rate
    function emergencyWithdraw() external {
        uint256 userShares = shares[msg.sender];
        require(userShares > 0, "no shares");
        
        shares[msg.sender] = 0;
        totalShares -= userShares;
        
        // VULN: uses totalAssetsCached which may be stale
        // attacker: donate to vault → emergencyWithdraw → capture donation
        uint256 amount = userShares * totalAssetsCached / (totalShares + userShares);
        want.transfer(msg.sender, amount);
    }

    // ========== VULN 6: Debt Ratio Manipulation (YIELD-DEBTRATIO-01) ==========

    // BUG #6: governance can change debt ratio to funnel assets to malicious strategy
    function updateDebtRatio(address strategy, uint256 newRatio) external {
        require(msg.sender == governance);
        // VULN: no timelock, no total ratio validation
        // governance immediately redirects all assets to compromised strategy
        strategies[strategy].debtRatio = newRatio;
        // Could exceed 100% total if combined with other strategies
    }

    // ========== VULN 7: Flash Deposit-Harvest-Withdraw (YIELD-FLASH-01) ==========

    // BUG #7: no deposit lock means flash deposit is possible
    function withdraw(uint256 sharesAmount) external returns (uint256 amountOut) {
        require(shares[msg.sender] >= sharesAmount, "insufficient");
        
        // VULN: no minimum lock time between deposit and withdraw
        // flash: deposit in same block as harvest, withdraw immediately after
        amountOut = sharesAmount * _totalAssets() / totalShares;
        
        // Withdrawal fee
        uint256 fee = amountOut * withdrawalFee / 10000;
        amountOut -= fee;
        
        shares[msg.sender] -= sharesAmount;
        totalShares -= sharesAmount;
        
        // Pull from strategies if vault balance insufficient
        uint256 vaultBalance = want.balanceOf(address(this));
        if (amountOut > vaultBalance) {
            uint256 needed = amountOut - vaultBalance;
            _withdrawFromStrategies(needed);
        }
        
        want.transfer(msg.sender, amountOut);
    }

    // ========== VULN 8: Strategy Loss Hiding (YIELD-LOSSHIDE-01) ==========

    // BUG #8: strategy doesn't report losses until forced
    function forceReportLoss(address strategy, uint256 lossAmount) external {
        require(msg.sender == governance);
        Strategy storage s = strategies[strategy];
        // VULN: governance can delay loss reporting indefinitely
        // share price remains inflated, early withdrawers get more than fair share
        s.totalLoss += lossAmount;
        s.totalDebt -= lossAmount;
        totalStrategyDebt -= lossAmount;
    }

    // ========== VULN 9: Reward Token Swap Front-run (YIELD-REWARDSWAP-01) ==========

    // BUG #9: selling reward tokens on DEX is front-runnable
    function sellRewards(uint256 amount) external {
        require(msg.sender == governance);
        rewardToken.approve(address(router), amount);
        // VULN: no minimum output, MEV sandwich on the swap
        uint256 received = router.swap(address(rewardToken), address(want), amount);
        // received could be much less than fair value due to sandwich
    }

    // ========== VULN 10: Management Fee Extraction (YIELD-MGMTFEE-01) ==========

    // BUG #10: management fee calculated on total assets including unrealized gains
    function collectManagementFee() external {
        uint256 elapsed = block.timestamp - lastReport;
        // VULN: fee on totalAssets which includes unrealized strategy gains
        // governance earns fee on paper profits that may never materialize
        uint256 fee = _totalAssets() * managementFee * elapsed / (10000 * 365 days);
        uint256 feeShares = fee * totalShares / _totalAssets();
        shares[feeRecipient] += feeShares;
        totalShares += feeShares;
    }

    // ========== VULN 11: Performance Fee on Unrealized (YIELD-PERFFEE-01) ==========

    // BUG #11: performance fee charged on strategy reported gain
    // gain might be unrealized / based on manipulable oracle
    // (embedded in harvest() function above)

    // ========== VULN 12: Locked Profit Manipulation (YIELD-LOCKEDPROF-01) ==========

    // BUG #12: lockedProfit degrades over time to prevent sandwich
    // but degradation rate is configurable by governance
    function setLockedProfitDegradation(uint256 newRate) external {
        require(msg.sender == governance);
        // VULN: set to 0 → no degradation → profit never unlocks
        // set to 1 → instant unlock → sandwich protection disabled
        lockedProfitDegradation = newRate;
    }

    function _calculateLockedProfit() internal view returns (uint256) {
        uint256 elapsed = block.timestamp - lastReport;
        if (lockedProfitDegradation == 0 || elapsed >= lockedProfitDegradation) {
            return 0;
        }
        return lockedProfit * (lockedProfitDegradation - elapsed) / lockedProfitDegradation;
    }

    // ========== VULN 13: Deposit Limit Bypass (YIELD-DEPOSITLIM-01) ==========

    // BUG #13: deposit limit checked on totalAssets, not including pending
    function depositWithPermit(uint256 amount, uint8 v, bytes32 r, bytes32 s) external returns (uint256) {
        // VULN: multiple deposits in same block can bypass limit
        // each deposit sees stale totalAssets before others are processed
        return this.deposit(amount);
    }

    // ========== VULN 14: Strategy Queue Ordering Attack (YIELD-QUEUE-01) ==========

    // BUG #14: withdrawal queue order determines which strategy is drained first
    function setWithdrawalQueue(address[] calldata queue) external {
        require(msg.sender == governance);
        // VULN: governance can reorder to drain specific strategy
        // preferentially pulling from competitors' strategies
        withdrawalQueue = queue;
    }

    // ========== VULN 15: Harvest Timing Manipulation (YIELD-TIMING-01) ==========

    // BUG #15: keeper can choose WHEN to harvest for MEV advantage
    function keeperHarvest(address strategy) external {
        Strategy storage s = strategies[strategy];
        // VULN: no required interval, keeper harvests when it maximizes MEV
        // e.g., front-runs large deposit with harvest to inflate share price
        require(block.timestamp >= s.lastReport + 1, "too soon");
        // 1 second minimum = effectively no minimum
    }

    // ========== VULN 16: Total Assets Desync (YIELD-DESYNC-01) ==========

    // BUG #16: totalAssets() includes strategy debt that may be inaccurate
    function _totalAssets() internal view returns (uint256) {
        // VULN: strategy debt is self-reported, may not match actual
        // vault balance + reported strategy debt ≠ true total assets
        return want.balanceOf(address(this)) + totalStrategyDebt - _calculateLockedProfit();
    }

    function updateTotalAssetsCache() external {
        // VULN: cached value immediately stale after any deposit/withdraw/harvest
        totalAssetsCached = _totalAssets();
    }

    // ========== VULN 17: Withdrawal Fee Avoidance (YIELD-WFEE-01) ==========

    // BUG #17: transfer shares to fresh address then withdraw—no fee history
    function transferShares(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount);
        shares[msg.sender] -= amount;
        // VULN: new address has no withdrawal fee cooldown
        // bypass withdrawal fee by transferring shares
        shares[to] += amount;
    }

    // ========== VULN 18: Underlying Protocol Exploit (YIELD-PASSTHRU-01) ==========

    // BUG #18: if underlying protocol (e.g., Aave, Compound) is exploited
    // strategy loss isn't capped, can exceed totalDebt
    // vault becomes insolvent
    // (this is a design-level vulnerability, not code-level)

    // ========== VULN 19: Vault Token Rebasing (YIELD-VAULTREBASE-01) ==========

    // BUG #19: vault share token doesn't handle rebasing underlying
    function depositRebasing(uint256 amount) external {
        uint256 balBefore = want.balanceOf(address(this));
        want.transferFrom(msg.sender, address(this), amount);
        uint256 balAfter = want.balanceOf(address(this));
        // VULN: actual received may differ from amount if want is rebasing
        // shares calculated on 'amount' not actual received
        uint256 sharesOut = amount * totalShares / _totalAssets(); // should use (balAfter - balBefore)
        shares[msg.sender] += sharesOut;
        totalShares += sharesOut;
    }

    // ========== VULN 20: Auto-Compound Slippage (YIELD-AUTOCOMP-01) ==========

    // BUG #20: auto-compounding rewards with no slippage protection
    function autoCompound() external {
        uint256 rewardBal = rewardToken.balanceOf(address(this));
        require(rewardBal > 0, "no rewards");
        rewardToken.approve(address(router), rewardBal);
        // VULN: minOutput = 0, sandwich attack on compound txs
        uint256 wantReceived = router.swap(address(rewardToken), address(want), rewardBal);
        // wantReceived could be manipulated to near-zero by MEV
    }

    // ========== Internal ==========

    function _withdrawFromStrategies(uint256 needed) internal {
        for (uint256 i = 0; i < withdrawalQueue.length && needed > 0; i++) {
            address strategy = withdrawalQueue[i];
            Strategy storage s = strategies[strategy];
            uint256 available = s.totalDebt;
            uint256 toWithdraw = needed > available ? available : needed;
            (bool ok, ) = strategy.call(abi.encodeWithSignature("withdraw(uint256)", toWithdraw));
            if (ok) {
                s.totalDebt -= toWithdraw;
                totalStrategyDebt -= toWithdraw;
                needed -= toWithdraw;
            }
        }
    }

    function addStrategy(address strategy, uint256 debtRatio) external {
        require(msg.sender == governance);
        strategies[strategy] = Strategy({
            strategyAddress: strategy,
            debtRatio: debtRatio,
            totalDebt: 0, totalGain: 0, totalLoss: 0,
            lastReport: block.timestamp,
            active: true
        });
        withdrawalQueue.push(strategy);
    }
}
