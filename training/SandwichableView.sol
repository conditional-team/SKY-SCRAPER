// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SandwichableView
 * @dev Training Contract #15 - View Function as Oracle Attack Vector
 * 
 * MASTER LEVEL VULNERABILITY:
 * 1. View function returns price/rate from state
 * 2. External protocols use this view as an "oracle"
 * 3. Attacker can manipulate state, exploit external protocol, restore state
 * 4. All in single atomic transaction = sandwich attack
 * 
 * REAL EXPLOIT: Read-only reentrancy on Curve, Balancer
 * 
 * CHAIN INTEGRATION:
 * - This contract's getRate() is used by Contract 07 (FlashLoanVictim)
 * - Manipulate rate → exploit victim → restore rate
 */

contract SandwichableView {
    // AMM-style reserves
    uint256 public reserve0;
    uint256 public reserve1;
    
    // LP token tracking
    mapping(address => uint256) public lpBalance;
    uint256 public totalLP;
    
    // Fee accumulator
    uint256 public accumulatedFees;
    
    // Last known values for "protection" (ineffective)
    uint256 public lastRate;
    uint256 public lastRateBlock;
    
    address public owner;
    bool public paused;
    
    event Swap(address indexed user, uint256 amountIn, uint256 amountOut, bool zeroForOne);
    event LiquidityAdded(address indexed provider, uint256 lp);
    event LiquidityRemoved(address indexed provider, uint256 lp);
    
    constructor(uint256 initialReserve0, uint256 initialReserve1) {
        reserve0 = initialReserve0;
        reserve1 = initialReserve1;
        totalLP = sqrt(initialReserve0 * initialReserve1);
        lpBalance[msg.sender] = totalLP;
        owner = msg.sender;
        lastRate = getRate();
        lastRateBlock = block.number;
    }
    
    // ============ VIEW FUNCTIONS (ORACLE-LIKE) ============
    
    /**
     * @dev Get current exchange rate
     * BUG: This is used as an oracle by external protocols
     * Manipulable via swap in same transaction!
     */
    function getRate() public view returns (uint256) {
        if (reserve1 == 0) return 0;
        return (reserve0 * 1e18) / reserve1;
    }
    
    /**
     * @dev Get LP token price
     * BUG: Manipulable - classic read-only reentrancy target
     */
    function getLPPrice() public view returns (uint256) {
        if (totalLP == 0) return 0;
        uint256 totalValue = reserve0 + (reserve1 * getRate() / 1e18);
        return (totalValue * 1e18) / totalLP;
    }
    
    /**
     * @dev Get "safe" rate with block check
     * BUG: Only checks if rate changed in PREVIOUS blocks
     * Same-block manipulation not detected!
     */
    function getSafeRate() external view returns (uint256) {
        // This doesn't protect against same-block manipulation!
        if (block.number == lastRateBlock) {
            // BUG: Returns current (manipulated) rate, not last known safe rate
            return getRate();
        }
        return lastRate;
    }
    
    /**
     * @dev TWAP-like rate (but broken)
     * BUG: Only uses last 2 data points, easily manipulable
     */
    function getTWAP() external view returns (uint256) {
        // Pretend TWAP with just last + current (useless)
        return (lastRate + getRate()) / 2;
    }
    
    // ============ SWAP (MANIPULATES RATE) ============
    
    /**
     * @dev Swap tokens - changes reserves and thus rate
     * This is the manipulation vector for sandwich
     */
    function swap(uint256 amountIn, bool zeroForOne) external returns (uint256 amountOut) {
        require(!paused, "Paused");
        require(amountIn > 0, "Zero amount");
        
        // Constant product formula
        uint256 k = reserve0 * reserve1;
        
        if (zeroForOne) {
            uint256 newReserve0 = reserve0 + amountIn;
            uint256 newReserve1 = k / newReserve0;
            amountOut = reserve1 - newReserve1;
            
            reserve0 = newReserve0;
            reserve1 = newReserve1;
        } else {
            uint256 newReserve1 = reserve1 + amountIn;
            uint256 newReserve0 = k / newReserve1;
            amountOut = reserve0 - newReserve0;
            
            reserve1 = newReserve1;
            reserve0 = newReserve0;
        }
        
        // Fee
        uint256 fee = amountOut / 1000; // 0.1%
        amountOut -= fee;
        accumulatedFees += fee;
        
        // BUG: Update lastRate AFTER swap, not before
        // External calls during this function see manipulated rate
        lastRate = getRate();
        lastRateBlock = block.number;
        
        emit Swap(msg.sender, amountIn, amountOut, zeroForOne);
    }
    
    /**
     * @dev Flash swap - allows manipulation and callback
     * Classic sandwich vector
     */
    function flashSwap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external {
        require(!paused, "Paused");
        require(amount0Out > 0 || amount1Out > 0, "Zero output");
        require(amount0Out < reserve0 && amount1Out < reserve1, "Insufficient liquidity");
        
        uint256 balance0Before = reserve0;
        uint256 balance1Before = reserve1;
        
        // Optimistically transfer
        if (amount0Out > 0) reserve0 -= amount0Out;
        if (amount1Out > 0) reserve1 -= amount1Out;
        
        // RATE IS NOW MANIPULATED!
        // External protocols reading getRate() see wrong value
        
        // Callback
        if (data.length > 0) {
            IFlashSwapCallback(to).flashSwapCallback(amount0Out, amount1Out, data);
        }
        
        // Verify repayment (simplified)
        require(reserve0 * reserve1 >= balance0Before * balance1Before, "K");
        
        lastRate = getRate();
        lastRateBlock = block.number;
    }
    
    // ============ LIQUIDITY ============
    
    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 lp) {
        // Calculate LP tokens
        if (totalLP == 0) {
            lp = sqrt(amount0 * amount1);
        } else {
            lp = min(
                (amount0 * totalLP) / reserve0,
                (amount1 * totalLP) / reserve1
            );
        }
        
        reserve0 += amount0;
        reserve1 += amount1;
        totalLP += lp;
        lpBalance[msg.sender] += lp;
        
        emit LiquidityAdded(msg.sender, lp);
    }
    
    function removeLiquidity(uint256 lp) external returns (uint256 amount0, uint256 amount1) {
        require(lpBalance[msg.sender] >= lp, "Insufficient LP");
        
        amount0 = (lp * reserve0) / totalLP;
        amount1 = (lp * reserve1) / totalLP;
        
        lpBalance[msg.sender] -= lp;
        totalLP -= lp;
        reserve0 -= amount0;
        reserve1 -= amount1;
        
        emit LiquidityRemoved(msg.sender, lp);
    }
    
    // ============ HELPERS ============
    
    function sqrt(uint256 x) internal pure returns (uint256 y) {
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }
    
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    
    function pause() external {
        require(msg.sender == owner, "Only owner");
        paused = true;
    }
    
    receive() external payable {}
}

interface IFlashSwapCallback {
    function flashSwapCallback(uint256 amount0, uint256 amount1, bytes calldata data) external;
}

/**
 * @dev External protocol that uses SandwichableView as oracle
 * This is what gets exploited
 */
contract VictimLending {
    SandwichableView public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    
    constructor(address _oracle) {
        oracle = SandwichableView(payable(_oracle));
    }
    
    /**
     * @dev Borrow using LP tokens as collateral
     * BUG: Uses manipulable getLPPrice() for valuation!
     */
    function borrowAgainstLP(uint256 lpAmount, uint256 borrowAmount) external {
        // Get LP price from oracle (manipulable!)
        uint256 lpPrice = oracle.getLPPrice();
        uint256 collateralValue = (lpAmount * lpPrice) / 1e18;
        
        // 80% LTV
        uint256 maxBorrow = (collateralValue * 80) / 100;
        require(borrowAmount <= maxBorrow, "Exceeds LTV");
        
        collateral[msg.sender] += lpAmount;
        debt[msg.sender] += borrowAmount;
    }
    
    /**
     * @dev Liquidate based on oracle price
     */
    function liquidate(address user) external {
        uint256 lpPrice = oracle.getLPPrice();
        uint256 collateralValue = (collateral[user] * lpPrice) / 1e18;
        uint256 requiredCollateral = (debt[user] * 100) / 80; // 80% LTV
        
        require(collateralValue < requiredCollateral, "Healthy");
        
        // Liquidate...
        delete collateral[user];
        delete debt[user];
    }
}
