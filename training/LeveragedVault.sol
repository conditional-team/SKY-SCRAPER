// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LeveragedVault
 * @dev Training Contract #63 - Leveraged DeFi Vault Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Recursive Borrowing Loop (LEV-RECURSE-01)
 * 2. Liquidation Price Manipulation (LEV-LIQPRICE-01)
 * 3. Leverage Ratio Overflow (LEV-RATIOOVERFLOW-01)
 * 4. Flash Leverage Attack (LEV-FLASHLEV-01)
 * 5. Deleverage Sandwich (LEV-DELEVSANDWICH-01)
 * 6. Collateral Factor Manipulation (LEV-COLFACTOR-01)
 * 7. Bad Debt Socialization (LEV-BADDEBT-01)
 * 8. Oracle-Based Leverage Exploit (LEV-ORACLELEV-01)
 * 9. Interest Accrual Skip (LEV-INTERESTSKIP-01)
 * 10. Leverage Token Depeg (LEV-TOKENDEPEG-01)
 * 11. Auto-Deleverage Failure (LEV-AUTODELFAIL-01)
 * 12. Margin Call Timing (LEV-MARGINCALL-01)
 * 13. Collateral Chain Breakage (LEV-COLCHAIN-01)
 * 14. Withdraw During Leverage (LEV-WITHDRAWLEV-01)
 * 15. Position Size Amplification (LEV-SIZEAMP-01)
 * 16. Funding Rate Drain (LEV-FUNDDRAIN-01)
 * 17. Strategy Migration Desync (LEV-MIGDESYNC-01)
 * 18. Health Factor Rounding (LEV-HEALTHROUND-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): LEV-*, leverage, liquidation, borrow, collateral
 * - Engine 2 (deep-semantic): recursive borrowing, margin logic
 * - Engine 13 (mev-analyzer): sandwich, flash leverage, liquidation MEV
 * - Engine 3 (state-desync): interest accrual, position tracking
 */

interface ILendingPool {
    function deposit(address asset, uint256 amount) external;
    function borrow(address asset, uint256 amount) external;
    function repay(address asset, uint256 amount) external;
    function getAccountData(address user) external view returns (
        uint256 totalCollateral, uint256 totalDebt, uint256 availableBorrow,
        uint256 liquidationThreshold, uint256 ltv, uint256 healthFactor
    );
}

interface IPriceOracle {
    function getPrice(address asset) external view returns (uint256);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract LeveragedVault {

    struct Position {
        address owner;
        address collateralAsset;
        address borrowAsset;
        uint256 collateralAmount;
        uint256 borrowedAmount;
        uint256 leverageRatio; // multiplied by 100 (300 = 3x)
        uint256 entryPrice;
        uint256 lastInterestUpdate;
        uint256 accruedInterest;
        bool active;
    }

    mapping(uint256 => Position) public positions;
    uint256 public nextPositionId;
    
    ILendingPool public lendingPool;
    IPriceOracle public oracle;
    address public owner;
    
    uint256 public maxLeverage = 1000; // 10x
    uint256 public liquidationThreshold = 11000; // 110%
    uint256 public interestRatePerSecond = 1e10; // ~31.5% APR
    uint256 public totalBadDebt;
    
    mapping(address => uint256) public totalCollateral;
    mapping(address => uint256) public totalBorrowed;
    
    bool public emergencyMode;
    uint256 public lastGlobalUpdate;

    constructor(address _pool, address _oracle) {
        lendingPool = ILendingPool(_pool);
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    // ========== VULN 1: Recursive Borrowing Loop (LEV-RECURSE-01) ==========

    // BUG #1: user can loop deposit-borrow-deposit to achieve arbitrarily high leverage
    function openLeveragedPosition(
        address collateralAsset,
        address borrowAsset,
        uint256 amount,
        uint256 targetLeverage
    ) external returns (uint256 posId) {
        require(targetLeverage <= maxLeverage, "too much leverage");
        
        IERC20(collateralAsset).transferFrom(msg.sender, address(this), amount);
        
        uint256 totalCollateralAmt = amount;
        uint256 totalBorrowed_;
        
        // VULN: loop compounds leverage beyond intended limit
        // each iteration deposits borrowed funds as more collateral
        uint256 currentAmount = amount;
        for (uint256 i = 0; i < 10; i++) {
            uint256 borrowAmt = currentAmount * 75 / 100; // 75% LTV each iter
            IERC20(collateralAsset).approve(address(lendingPool), currentAmount);
            lendingPool.deposit(collateralAsset, currentAmount);
            lendingPool.borrow(borrowAsset, borrowAmt);
            
            // Swap borrowAsset → collateralAsset (simplified)
            currentAmount = borrowAmt; // assume 1:1 for simplicity
            totalCollateralAmt += currentAmount;
            totalBorrowed_ += borrowAmt;
        }
        
        posId = nextPositionId++;
        positions[posId] = Position({
            owner: msg.sender,
            collateralAsset: collateralAsset,
            borrowAsset: borrowAsset,
            collateralAmount: totalCollateralAmt,
            borrowedAmount: totalBorrowed_,
            leverageRatio: totalCollateralAmt * 100 / amount,
            entryPrice: oracle.getPrice(collateralAsset),
            lastInterestUpdate: block.timestamp,
            accruedInterest: 0,
            active: true
        });
    }

    // ========== VULN 2: Liquidation Price Manipulation (LEV-LIQPRICE-01) ==========

    // BUG #2: liquidation uses spot oracle price, manipulable via flash loan
    function liquidatePosition(uint256 posId) external {
        Position storage pos = positions[posId];
        require(pos.active, "not active");
        
        // VULN: price from oracle at this instant, flash-loan manipulable
        uint256 price = oracle.getPrice(pos.collateralAsset);
        uint256 collateralValue = pos.collateralAmount * price / 1e18;
        uint256 debtValue = pos.borrowedAmount + pos.accruedInterest;
        
        // Health factor = collateralValue * 10000 / debtValue
        uint256 healthFactor = collateralValue * 10000 / (debtValue + 1);
        require(healthFactor < liquidationThreshold, "still healthy");
        
        pos.active = false;
        // Liquidator gets collateral at discount
        IERC20(pos.collateralAsset).transfer(msg.sender, pos.collateralAmount);
    }

    // ========== VULN 3: Leverage Ratio Overflow (LEV-RATIOOVERFLOW-01) ==========

    // BUG #3: leverage calculation overflow with large collateral amounts
    function computeLeverage(uint256 collateral, uint256 debt) external pure returns (uint256) {
        // VULN: if collateral * 100 overflows, result wraps around
        // attacker can create "negative" leverage position
        unchecked {
            return collateral * 100 / (collateral - debt);
        }
        // If debt > collateral, division by negative (underflow) → huge number
    }

    // ========== VULN 4: Flash Leverage Attack (LEV-FLASHLEV-01) ==========

    // BUG #4: flash loan → deposit → borrow → repay flash loan → keep leverage
    function flashLeverageCallback(
        address asset, uint256 amount, uint256 premium, bytes calldata params
    ) external returns (bool) {
        // VULN: flash loan used to create leveraged position without own capital
        // deposit flash loaned funds → borrow against them → repay flash  
        // Keep borrowed amount as profit
        (address collateral, uint256 targetBorrow) = abi.decode(params, (address, uint256));
        
        IERC20(asset).approve(address(lendingPool), amount);
        lendingPool.deposit(asset, amount);
        lendingPool.borrow(collateral, targetBorrow);
        
        // Repay flash loan with borrowed funds
        IERC20(asset).transfer(msg.sender, amount + premium);
        return true;
    }

    // ========== VULN 5: Deleverage Sandwich (LEV-DELEVSANDWICH-01) ==========

    // BUG #5: deleverage operation swaps on DEX, sandwichable
    function deleverage(uint256 posId, uint256 amount) external {
        Position storage pos = positions[posId];
        require(pos.owner == msg.sender, "not owner");
        
        // VULN: repay involves selling collateral on DEX
        // attacker sandwiches: front-run push price down, deleverage at worse rate
        pos.collateralAmount -= amount;
        lendingPool.repay(pos.borrowAsset, amount);
        pos.borrowedAmount -= amount;
    }

    // ========== VULN 6: Collateral Factor Manipulation (LEV-COLFACTOR-01) ==========

    mapping(address => uint256) public collateralFactors; // basis points

    // BUG #6: governance changes collateral factor
    // existing positions can become instantly liquidatable
    function setCollateralFactor(address asset, uint256 factor) external {
        require(msg.sender == owner, "not owner");
        // VULN: no time-lock, no gradual reduction
        // dropping factor from 80% to 60% instantly puts positions underwater
        collateralFactors[asset] = factor;
    }

    // ========== VULN 7: Bad Debt Socialization (LEV-BADDEBT-01) ==========

    // BUG #7: underwater position's bad debt spread to all depositors
    function socializeBadDebt(uint256 posId) external {
        Position storage pos = positions[posId];
        uint256 price = oracle.getPrice(pos.collateralAsset);
        uint256 collateralValue = pos.collateralAmount * price / 1e18;
        uint256 debt = pos.borrowedAmount + pos.accruedInterest;
        
        if (debt > collateralValue) {
            uint256 badDebt = debt - collateralValue;
            // VULN: bad debt subtracted from all depositors' shares equally
            // whale can self-liquidate at a loss, socializing the loss
            totalBadDebt += badDebt;
        }
        pos.active = false;
    }

    // ========== VULN 8: Oracle-Based Leverage Exploit (LEV-ORACLELEV-01) ==========

    // BUG #8: open position at stale oracle price, close at updated price
    function adjustPosition(uint256 posId, int256 collateralDelta) external {
        Position storage pos = positions[posId];
        require(pos.owner == msg.sender, "not owner");
        
        // VULN: uses oracle.getPrice() which may be stale
        // attacker knows real price moved 5% but oracle hasn't updated
        // takes leveraged position based on stale price → profit when oracle updates
        uint256 price = oracle.getPrice(pos.collateralAsset);
        
        if (collateralDelta > 0) {
            pos.collateralAmount += uint256(collateralDelta);
        } else {
            pos.collateralAmount -= uint256(-collateralDelta);
        }
        pos.entryPrice = price;
    }

    // ========== VULN 9: Interest Accrual Skip (LEV-INTERESTSKIP-01) ==========

    // BUG #9: interest only accrues when position is touched
    function accrueInterest(uint256 posId) public {
        Position storage pos = positions[posId];
        uint256 elapsed = block.timestamp - pos.lastInterestUpdate;
        
        // VULN: if no one touches position for months, interest doesn't compound
        // borrower's effective rate < stated rate
        pos.accruedInterest += pos.borrowedAmount * elapsed * interestRatePerSecond / 1e18;
        pos.lastInterestUpdate = block.timestamp;
    }

    // ========== VULN 10: Leverage Token Depeg (LEV-TOKENDEPEG-01) ==========

    mapping(address => uint256) public leverageTokenSupply;
    mapping(address => mapping(address => uint256)) public leverageTokenBalance;

    // BUG #10: leverage token represents share of vault's leveraged position
    // but token price depegs from NAV during volatility
    function mintLeverageToken(uint256 posId, uint256 amount) external {
        Position storage pos = positions[posId];
        // VULN: mint at NAV but token trades on DEX at discount during panic
        // arbitrageurs can't profitably redeem → death spiral
        leverageTokenBalance[pos.collateralAsset][msg.sender] += amount;
        leverageTokenSupply[pos.collateralAsset] += amount;
    }

    // ========== VULN 11: Auto-Deleverage Failure (LEV-AUTODELFAIL-01) ==========

    // BUG #11: auto-deleverage mechanism fails during high gas or congestion
    function autoDeleverage(uint256 posId) external {
        Position storage pos = positions[posId];
        uint256 price = oracle.getPrice(pos.collateralAsset);
        uint256 healthFactor = pos.collateralAmount * price * 10000 / 
            ((pos.borrowedAmount + pos.accruedInterest + 1) * 1e18);
        
        // VULN: auto-deleverage requires specific gas limit
        // if gas price spikes, keepers can't afford to call → position goes underwater
        require(healthFactor < 12000, "not in danger zone");
        
        uint256 deleverageAmt = pos.borrowedAmount / 4;
        pos.collateralAmount -= deleverageAmt;
        pos.borrowedAmount -= deleverageAmt;
    }

    // ========== VULN 12: Margin Call Timing (LEV-MARGINCALL-01) ==========

    mapping(uint256 => uint256) public marginCallTimestamp;

    // BUG #12: margin call gives fixed time to add collateral
    // but price can crash further during grace period
    function issueMarginCall(uint256 posId) external {
        // VULN: 24-hour grace period during which position is protected
        // price can drop 50% in 24 hours, turning small deficit into huge bad debt
        marginCallTimestamp[posId] = block.timestamp;
    }

    function resolveMarginCall(uint256 posId) external {
        require(block.timestamp >= marginCallTimestamp[posId] + 24 hours, "grace period");
        // Position can only be liquidated after grace period
    }

    // ========== VULN 13: Collateral Chain Breakage (LEV-COLCHAIN-01) ==========

    // BUG #13: collateral is itself a receipt token (aToken, cToken)
    // if underlying lending pool is exploited, collateral becomes worthless
    function acceptReceiptTokenCollateral(address receiptToken, uint256 amount) external {
        IERC20(receiptToken).transferFrom(msg.sender, address(this), amount);
        // VULN: assuming receiptToken is always redeemable 1:1 for underlying
        // if underlying pool is hacked/paused, receipt is worthless
        totalCollateral[receiptToken] += amount;
    }

    // ========== VULN 14: Withdraw During Leverage (LEV-WITHDRAWLEV-01) ==========

    // BUG #14: partial withdrawal from leveraged position
    function withdrawCollateral(uint256 posId, uint256 amount) external {
        Position storage pos = positions[posId];
        require(pos.owner == msg.sender, "not owner");
        require(pos.collateralAmount >= amount, "too much");
        
        pos.collateralAmount -= amount;
        // VULN: no health factor check after withdrawal
        // position can go underwater after withdrawal
        IERC20(pos.collateralAsset).transfer(msg.sender, amount);
    }

    // ========== VULN 15: Position Size Amplification (LEV-SIZEAMP-01) ==========

    // BUG #15: multiple positions compound to exceed protocol-wide limits
    function getEffectiveExposure(address user) external view returns (uint256 total) {
        // VULN: each position is checked individually, but total exposure unlimited
        // user opens 100 positions at 9x leverage each → effective 900x
        for (uint256 i = 0; i < nextPositionId; i++) {
            if (positions[i].owner == user && positions[i].active) {
                total += positions[i].collateralAmount;
            }
        }
    }

    // ========== VULN 16: Funding Rate Drain (LEV-FUNDDRAIN-01) ==========

    int256 public fundingRate; // positive = longs pay shorts

    // BUG #16: funding rate set by oracle, not by actual long/short imbalance
    function setFundingRate(int256 newRate) external {
        require(msg.sender == owner, "not owner");
        // VULN: manipulated funding rate drains one side
        // set hugely negative → shorts pay longs → drain short positions
        fundingRate = newRate;
    }

    // ========== VULN 17: Strategy Migration Desync (LEV-MIGDESYNC-01) ==========

    address public activeStrategy;

    // BUG #17: migrating vault strategy while positions are open
    function migrateStrategy(address newStrategy) external {
        require(msg.sender == owner, "not owner");
        // VULN: existing positions reference old strategy's state
        // new strategy has different pricing, different collateral factors
        // positions become instantly underwater or over-leveraged
        activeStrategy = newStrategy;
    }

    // ========== VULN 18: Health Factor Rounding (LEV-HEALTHROUND-01) ==========

    // BUG #18: health factor calculation loses precision at extreme leverage
    function getHealthFactor(uint256 posId) external view returns (uint256) {
        Position storage pos = positions[posId];
        uint256 price = oracle.getPrice(pos.collateralAsset);
        
        // VULN: at 10x leverage, collateral ≈ 1.1x debt
        // rounding error: 110001 vs 110000 = difference between safe and liquidatable
        uint256 collateralValue = pos.collateralAmount * price;
        uint256 debt = (pos.borrowedAmount + pos.accruedInterest) * 1e18;
        
        // Integer division loses precision
        return collateralValue * 10000 / (debt + 1);
    }

    // ========== Admin ==========

    function setEmergencyMode(bool mode) external {
        require(msg.sender == owner);
        emergencyMode = mode;
    }

    receive() external payable {}
}
