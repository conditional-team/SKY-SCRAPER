// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ConcentratedLiquidityMEV
 * @dev Training Contract #50 - Concentrated Liquidity MEV Exploits (Uniswap V3 style)
 *
 * VULNERABILITY CATEGORIES:
 * 1. JIT Liquidity Attack (CLMEV-JIT-01)
 * 2. Range Order Sniping (CLMEV-RANGE-01)
 * 3. Tick Crossing Gas Griefing (CLMEV-TICKGAS-01)
 * 4. Position Migration Drain (CLMEV-MIGRATE-01)
 * 5. Fee Compounding Front-run (CLMEV-FEECOMP-01)
 * 6. LP Sandwich (CLMEV-LPSANDWICH-01)
 * 7. Oracle TWAP Manipulation via CL (CLMEV-TWAP-01)
 * 8. Stale Tick Bitmap Exploit (CLMEV-BITMAP-01)
 * 9. Multi-Hop Route Extraction (CLMEV-MULTIHOP-01)
 * 10. Flash Loan Liquidity Manipulation (CLMEV-FLASHLIQ-01)
 * 11. Concentrated Impermanent Loss Amplification (CLMEV-IL-01)
 * 12. Protocol Fee Switch Front-run (CLMEV-PROTOFEE-01)
 * 13. NFT Position Transfer Exploit (CLMEV-NFTPOS-01)
 * 14. Liquidity Bootstrapping Pool Snipe (CLMEV-LBP-01)
 * 15. Reward Distribution Sandwich (CLMEV-REWARD-01)
 * 16. Price Impact Underestimation (CLMEV-IMPACT-01)
 * 17. Cross-Pool Atomic Arbitrage (CLMEV-XPOOL-01)
 * 18. Limit Order Execution Frontrun (CLMEV-LIMIT-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): CLMEV-*, JIT, sandwich, TWAP manipulation
 * - Engine 2 (deep-semantic): tick crossing logic, fee accounting
 * - Engine 13 (mev-analyzer): sandwich, front-run, atomic arb
 * - Engine 4 (temporal-analyzer): TWAP window, staleness
 */

interface IERC20CL {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface INonfungiblePositionManager {
    function positions(uint256 tokenId) external view returns (
        uint96 nonce, address operator, address token0, address token1,
        uint24 fee, int24 tickLower, int24 tickUpper, uint128 liquidity,
        uint256 feeGrowthInside0, uint256 feeGrowthInside1,
        uint128 tokensOwed0, uint128 tokensOwed1
    );
}

contract ConcentratedLiquidityPool {
    struct Position {
        address owner;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint256 feeGrowthInside0Last;
        uint256 feeGrowthInside1Last;
        uint128 tokensOwed0;
        uint128 tokensOwed1;
    }

    struct Slot0 {
        uint160 sqrtPriceX96;
        int24 tick;
        uint16 observationIndex;
        uint16 observationCardinality;
        uint8 feeProtocol;
        bool unlocked;
    }

    struct Observation {
        uint32 blockTimestamp;
        int56 tickCumulative;
        uint160 secondsPerLiquidityCumulativeX128;
        bool initialized;
    }

    IERC20CL public token0;
    IERC20CL public token1;
    uint24 public fee;
    int24 public tickSpacing;
    
    Slot0 public slot0;
    mapping(bytes32 => Position) public positions;
    mapping(int24 => uint128) public tickLiquidity;
    Observation[65535] public observations;

    uint256 public feeGrowthGlobal0X128;
    uint256 public feeGrowthGlobal1X128;
    uint128 public liquidity;
    uint256 public protocolFees0;
    uint256 public protocolFees1;
    
    address public factory;
    address public owner;

    // Reward distribution
    mapping(bytes32 => uint256) public rewardDebt;
    uint256 public accRewardPerLiquidity;
    IERC20CL public rewardToken;

    constructor(address _token0, address _token1, uint24 _fee) {
        token0 = IERC20CL(_token0);
        token1 = IERC20CL(_token1);
        fee = _fee;
        tickSpacing = 60;
        owner = msg.sender;
        slot0.unlocked = true;
    }

    modifier lock() {
        require(slot0.unlocked, "locked");
        slot0.unlocked = false;
        _;
        slot0.unlocked = true;
    }

    // ========== VULN 1: JIT Liquidity Attack (CLMEV-JIT-01) ==========

    // BUG #1: MEV bot adds concentrated liquidity right before large swap
    // captures most fees, removes liquidity in same block
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external lock returns (uint256 amount0, uint256 amount1) {
        require(amount > 0, "zero liquidity");
        
        bytes32 posKey = keccak256(abi.encodePacked(recipient, tickLower, tickUpper));
        Position storage pos = positions[posKey];
        
        // VULN: no minimum time requirement for liquidity provision
        // JIT bot adds + removes in same block, extracting swap fees
        pos.owner = recipient;
        pos.tickLower = tickLower;
        pos.tickUpper = tickUpper;
        pos.liquidity += amount;
        
        liquidity += amount;
        
        // Calculate token amounts (simplified)
        amount0 = uint256(amount) * 1e18 / uint256(uint160(slot0.sqrtPriceX96) + 1);
        amount1 = uint256(amount) * uint256(uint160(slot0.sqrtPriceX96)) / 1e18;
        
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
    }

    // ========== VULN 2: Range Order Sniping (CLMEV-RANGE-01) ==========

    // BUG #2: range orders (single-sided liquidity) are visible on-chain
    // sniper detects pending swap that will cross into range, front-runs to add own range
    function mintRangeOrder(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external lock returns (uint256 tokenAmount) {
        // VULN: range order parameters are public, MEV can front-run
        require(tickLower < tickUpper, "invalid range");
        bytes32 posKey = keccak256(abi.encodePacked(msg.sender, tickLower, tickUpper));
        positions[posKey].liquidity += amount;
        positions[posKey].owner = msg.sender;
        positions[posKey].tickLower = tickLower;
        positions[posKey].tickUpper = tickUpper;
        
        tokenAmount = uint256(amount);
        token0.transferFrom(msg.sender, address(this), tokenAmount);
        return tokenAmount;
    }

    // ========== VULN 3: Tick Crossing Gas Griefing (CLMEV-TICKGAS-01) ==========

    // BUG #3: each tick crossing costs extra gas
    // attacker creates many initialized ticks to grief other users' swaps
    function initializeTick(int24 tick) external {
        // VULN: anyone can initialize a tick with 1 wei of liquidity
        // making swaps that cross many ticks extremely expensive
        require(tick % tickSpacing == 0, "invalid tick");
        tickLiquidity[tick] += 1; // minimal liquidity, maximum gas cost per crossing
    }

    // ========== VULN 4: Position Migration Drain (CLMEV-MIGRATE-01) ==========

    // BUG #4: migration from V3 to V4 allows draining uncollected fees
    function migratePosition(
        bytes32 oldPosKey,
        address newPool,
        int24 newTickLower,
        int24 newTickUpper
    ) external {
        Position storage pos = positions[oldPosKey];
        require(pos.owner == msg.sender, "not owner");
        
        // VULN: collects fees before migration but doesn't update feeGrowth
        // attacker can claim fees twice: once during migration, once from new pool
        uint256 fees0 = pos.tokensOwed0;
        uint256 fees1 = pos.tokensOwed1;
        
        if (fees0 > 0) token0.transfer(msg.sender, fees0);
        if (fees1 > 0) token1.transfer(msg.sender, fees1);
        
        // Transfer liquidity to new pool without zeroing fees in old pool
        uint128 liq = pos.liquidity;
        pos.liquidity = 0;
        liquidity -= liq;
        // pos.tokensOwed0/1 NOT zeroed—can claim again
    }

    // ========== VULN 5: Fee Compounding Front-run (CLMEV-FEECOMP-01) ==========

    // BUG #5: fee auto-compounding is front-runnable
    // attacker adds liquidity before compound, gets share of newly compounded fees
    function compoundFees(bytes32 posKey) external {
        Position storage pos = positions[posKey];
        // VULN: no time-lock between fee accrual and compound
        // front-runner: add liquidity → compound → remove liquidity
        uint128 feeLiq0 = uint128(pos.tokensOwed0 * uint256(pos.liquidity) / 1e18);
        pos.liquidity += feeLiq0;
        pos.tokensOwed0 = 0;
        pos.tokensOwed1 = 0;
        liquidity += feeLiq0;
    }

    // ========== VULN 6: LP Sandwich (CLMEV-LPSANDWICH-01) ==========

    // BUG #6: swap function has no MEV protection
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external lock returns (int256 amount0, int256 amount1) {
        // VULN: no deadline parameter, no private mempool assumption
        // standard sandwich: push price → victim swaps at worse price → reverse
        
        uint256 feeAmount;
        if (amountSpecified > 0) {
            feeAmount = uint256(amountSpecified) * fee / 1e6;
            amount0 = amountSpecified;
            amount1 = -amountSpecified + int256(feeAmount);
        } else {
            amount0 = amountSpecified;
            amount1 = -amountSpecified;
        }

        // Update price
        if (zeroForOne) {
            slot0.tick -= 1;
        } else {
            slot0.tick += 1;
        }

        // Update fee growth
        if (liquidity > 0) {
            feeGrowthGlobal0X128 += feeAmount * 1e18 / uint256(liquidity);
        }

        // Transfer tokens
        if (amount0 > 0) {
            token0.transferFrom(msg.sender, address(this), uint256(amount0));
        } else {
            token0.transfer(recipient, uint256(-amount0));
        }
        if (amount1 > 0) {
            token1.transferFrom(msg.sender, address(this), uint256(amount1));
        } else {
            token1.transfer(recipient, uint256(-amount1));
        }
    }

    // ========== VULN 7: Oracle TWAP Manipulation (CLMEV-TWAP-01) ==========

    // BUG #7: short TWAP window is manipulable with concentrated liquidity
    function observe(uint32[] calldata secondsAgos) 
        external view returns (int56[] memory tickCumulatives, uint160[] memory) 
    {
        tickCumulatives = new int56[](secondsAgos.length);
        uint160[] memory secPerLiq = new uint160[](secondsAgos.length);
        
        for (uint256 i = 0; i < secondsAgos.length; i++) {
            // VULN: TWAP from concentrated pool is manipulable
            // attacker moves tick with minimal capital in low-liquidity range
            // then moves it back—TWAP reflects manipulation
            uint16 idx = slot0.observationIndex;
            tickCumulatives[i] = observations[idx].tickCumulative;
        }
        return (tickCumulatives, secPerLiq);
    }

    // ========== VULN 8: Stale Tick Bitmap Exploit (CLMEV-BITMAP-01) ==========

    mapping(int16 => uint256) public tickBitmap;

    // BUG #8: tick bitmap updates lag behind actual liquidity changes
    // cross-tick swap may skip freshly initialized ticks
    function updateTickBitmap(int24 tick, bool active) external {
        int16 wordPos = int16(tick >> 8);
        uint8 bitPos = uint8(int8(tick % 256));
        // VULN: bitmap update in separate tx from liquidity change
        // swap between these txs uses stale bitmap => wrong routing
        if (active) {
            tickBitmap[wordPos] |= (1 << bitPos);
        } else {
            tickBitmap[wordPos] &= ~(1 << bitPos);
        }
    }

    // ========== VULN 9: Multi-Hop Route Extraction (CLMEV-MULTIHOP-01) ==========

    // BUG #9: multi-hop swap exposes intermediate prices to MEV
    function multiHopSwap(
        address[] calldata path,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        amountOut = amountIn;
        for (uint256 i = 0; i < path.length - 1; i++) {
            // VULN: each intermediate swap is independently sandwichable
            // MEV bot profits at each hop, victim gets worst price
            amountOut = amountOut * 997 / 1000; // simplified fee
        }
        require(amountOut >= minAmountOut, "slippage");
    }

    // ========== VULN 10: Flash Loan Liquidity Manipulation (CLMEV-FLASHLIQ-01) ==========

    // BUG #10: flash loan → add liquidity → swap → remove liquidity → repay
    // zero-cost manipulation of pool price and fee extraction
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external lock {
        uint256 balance0Before = token0.balanceOf(address(this));
        uint256 balance1Before = token1.balanceOf(address(this));
        
        if (amount0 > 0) token0.transfer(recipient, amount0);
        if (amount1 > 0) token1.transfer(recipient, amount1);
        
        // VULN: callback allows all pool operations during flash
        // including mint/burn/swap—breaks flash accounting
        (bool ok, ) = recipient.call(data);
        require(ok, "flash callback failed");
        
        // Check repayment
        require(token0.balanceOf(address(this)) >= balance0Before, "flash0");
        require(token1.balanceOf(address(this)) >= balance1Before, "flash1");
    }

    // ========== VULN 11: Concentrated IL Amplification (CLMEV-IL-01) ==========

    // BUG #11: narrow range positions have massive impermanent loss
    // attacker moves price out of range, LP suffers 100% conversion to one side
    function getPositionValue(bytes32 posKey) external view returns (uint256 value0, uint256 value1) {
        Position storage pos = positions[posKey];
        int24 currentTick = slot0.tick;
        
        // VULN: if tick moves outside position range, LP is 100% one-sided
        // attacker with enough capital can force range exit on target LP
        if (currentTick < pos.tickLower) {
            // All value in token0—maximum IL for LP expecting balanced
            value0 = uint256(pos.liquidity);
            value1 = 0;
        } else if (currentTick >= pos.tickUpper) {
            value0 = 0;
            value1 = uint256(pos.liquidity);
        } else {
            value0 = uint256(pos.liquidity) / 2;
            value1 = uint256(pos.liquidity) / 2;
        }
    }

    // ========== VULN 12: Protocol Fee Switch Front-run (CLMEV-PROTOFEE-01) ==========

    // BUG #12: governance enables protocol fee switch
    // MEV actors front-run switch to extract fees before protocol starts collecting
    function setProtocolFee(uint8 feeProtocol) external {
        require(msg.sender == owner, "not owner");
        // VULN: no timelock, instant switch
        // front-runner removes all liquidity before fee kicks in
        slot0.feeProtocol = feeProtocol;
    }

    // ========== VULN 13: NFT Position Transfer Exploit (CLMEV-NFTPOS-01) ==========

    // BUG #13: position NFT transfer doesn't transfer uncollected fees
    // buyer of NFT loses accrued fees to seller
    function transferPosition(bytes32 oldKey, address newOwner) external {
        Position storage pos = positions[oldKey];
        require(pos.owner == msg.sender, "not owner");
        // VULN: fees accrued to old key, new owner can't claim them
        // seller should collect fees before transfer, but function doesn't enforce it
        bytes32 newKey = keccak256(abi.encodePacked(newOwner, pos.tickLower, pos.tickUpper));
        positions[newKey] = pos;
        positions[newKey].owner = newOwner;
        // tokensOwed still associated with old key
        delete positions[oldKey];
    }

    // ========== VULN 14: Liquidity Bootstrapping Pool Snipe (CLMEV-LBP-01) ==========

    bool public lbpActive;
    uint256 public lbpStartPrice;
    uint256 public lbpEndPrice;
    uint256 public lbpStartTime;
    uint256 public lbpDuration;

    // BUG #14: LBP price curve is predictable, sniper buys at exact bottom
    function lbpSwap(uint256 amountIn) external returns (uint256 amountOut) {
        require(lbpActive, "LBP not active");
        uint256 elapsed = block.timestamp - lbpStartTime;
        // VULN: linear price curve is 100% predictable
        // bot calculates exact moment price reaches target, snipes
        uint256 currentPrice = lbpStartPrice - (lbpStartPrice - lbpEndPrice) * elapsed / lbpDuration;
        amountOut = amountIn * 1e18 / currentPrice;
    }

    // ========== VULN 15: Reward Distribution Sandwich (CLMEV-REWARD-01) ==========

    // BUG #15: reward distribution to LPs is sandwichable
    function distributeRewards(uint256 rewardAmount) external {
        require(liquidity > 0, "no liquidity");
        rewardToken.transferFrom(msg.sender, address(this), rewardAmount);
        // VULN: attacker adds massive liquidity before this tx
        // captures majority of rewards, removes liquidity after
        accRewardPerLiquidity += rewardAmount * 1e18 / uint256(liquidity);
    }

    function claimRewards(bytes32 posKey) external {
        Position storage pos = positions[posKey];
        require(pos.owner == msg.sender, "not owner");
        uint256 pending = uint256(pos.liquidity) * accRewardPerLiquidity / 1e18 - rewardDebt[posKey];
        rewardDebt[posKey] = uint256(pos.liquidity) * accRewardPerLiquidity / 1e18;
        if (pending > 0) {
            rewardToken.transfer(msg.sender, pending);
        }
    }

    // ========== VULN 16: Price Impact Underestimation (CLMEV-IMPACT-01) ==========

    // BUG #16: quote function doesn't account for tick crossings
    function quoteSwap(bool zeroForOne, int256 amountSpecified) external view returns (int256 estimated) {
        // VULN: simple constant-product estimate ignores concentrated liquidity
        // actual swap crosses multiple ticks with varying liquidity
        // user gets much worse price than quoted
        estimated = amountSpecified * int256(uint256(slot0.sqrtPriceX96)) / 1e18;
    }

    // ========== VULN 17: Cross-Pool Atomic Arbitrage (CLMEV-XPOOL-01) ==========

    address[] public connectedPools;

    // BUG #17: price discrepancy between pools of same pair (different fee tiers)
    // allows risk-free atomic arbitrage
    function addConnectedPool(address pool) external {
        require(msg.sender == owner);
        // VULN: multiple fee-tier pools for same pair create arb opportunities
        // MEV bots continuously extract value from LPs across pools
        connectedPools.push(pool);
    }

    // ========== VULN 18: Limit Order Execution Frontrun (CLMEV-LIMIT-01) ==========

    struct LimitOrder {
        address maker;
        int24 tickTarget;
        uint256 amount;
        bool zeroForOne;
        bool executed;
    }
    LimitOrder[] public limitOrders;

    // BUG #18: on-chain limit orders are visible and front-runnable
    function placeLimitOrder(int24 tickTarget, uint256 amount, bool zeroForOne) external {
        // VULN: limit order params are public
        // MEV bot pushes price to tick target, executes their own before victim
        limitOrders.push(LimitOrder({
            maker: msg.sender,
            tickTarget: tickTarget,
            amount: amount,
            zeroForOne: zeroForOne,
            executed: false
        }));
    }

    function executeLimitOrder(uint256 orderId) external {
        LimitOrder storage order = limitOrders[orderId];
        require(!order.executed, "already executed");
        require(slot0.tick == order.tickTarget || 
                (order.zeroForOne && slot0.tick <= order.tickTarget) ||
                (!order.zeroForOne && slot0.tick >= order.tickTarget), "not at target");
        // VULN: executor chooses order, can cherry-pick profitable ones
        order.executed = true;
    }

    // Admin
    function setRewardToken(address _reward) external {
        require(msg.sender == owner);
        rewardToken = IERC20CL(_reward);
    }

    function initLBP(uint256 startPrice, uint256 endPrice, uint256 duration) external {
        require(msg.sender == owner);
        lbpActive = true;
        lbpStartPrice = startPrice;
        lbpEndPrice = endPrice;
        lbpStartTime = block.timestamp;
        lbpDuration = duration;
    }

    function burn(bytes32 posKey, uint128 amount) external lock {
        Position storage pos = positions[posKey];
        require(pos.owner == msg.sender, "not owner");
        require(pos.liquidity >= amount, "insufficient");
        pos.liquidity -= amount;
        liquidity -= amount;
    }
}
