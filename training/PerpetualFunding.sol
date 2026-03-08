// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PerpetualFunding
 * @dev Training Contract #48 - Perpetual Exchange & Funding Rate Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Funding Rate Manipulation (PERP-FUND-01)
 * 2. Mark Price vs Index Price Divergence (PERP-MARK-01)
 * 3. Liquidation Cascade Trigger (PERP-LIQ-01)
 * 4. Insurance Fund Drain (PERP-INSURE-01)
 * 5. Position Size Overflow (PERP-SIZE-01)
 * 6. Delayed Liquidation Profit (PERP-DELAY-01)
 * 7. Oracle Front-run on Position Open (PERP-ORACLE-01)
 * 8. Cross-Margin Contagion (PERP-XMARGIN-01)
 * 9. ADL Priority Manipulation (PERP-ADL-01)
 * 10. Isolated Margin Escape (PERP-ISO-01)
 * 11. Leverage Ratchet Attack (PERP-LEV-01)
 * 12. Unrealized PnL Withdrawal (PERP-PNL-01)
 * 13. Stop-Loss Hunting via Spike (PERP-STOPLOSS-01)
 * 14. Max Open Interest Bypass (PERP-OI-01)
 * 15. Fee Tier Manipulation (PERP-FEETIER-01)
 * 16. Late Close Penalty Avoidance (PERP-LATECLOSE-01)
 * 17. Partial Liquidation Gaming (PERP-PARTLIQ-01)
 * 18. Keeper Bot Incentive Theft (PERP-KEEPER-01)
 * 19. Funding Accrual Timestamp Gaming (PERP-TIMESTAMP-01)
 * 20. Settlement Price Manipulation (PERP-SETTLE-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): PERP-*, liquidation, funding, oracle
 * - Engine 2 (deep-semantic): PnL calculation, margin logic
 * - Engine 4 (temporal-analyzer): timestamp gaming, delayed liquidation
 * - Engine 13 (mev-analyzer): oracle front-run, stop-loss hunting
 */

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
    function getMarkPrice(address token) external view returns (uint256);
}

contract PerpetualExchange {
    struct Position {
        address trader;
        address market;
        int256 size;        // positive = long, negative = short
        uint256 collateral;
        uint256 entryPrice;
        uint256 lastFundingIndex;
        bool isIsolated;
        uint256 leverage;
        uint256 openTimestamp;
    }

    struct Market {
        address token;
        int256 fundingRate;           // per-hour funding rate
        uint256 longOpenInterest;
        uint256 shortOpenInterest;
        uint256 maxOpenInterest;
        uint256 lastFundingTime;
        uint256 cumulativeFundingIndex;
        uint256 markPrice;
        uint256 indexPrice;
    }

    mapping(bytes32 => Position) public positions;
    mapping(address => Market) public markets;
    mapping(address => uint256) public traderBalances;
    mapping(address => uint256) public traderVolume;     // for fee tiers
    
    uint256 public insuranceFund;
    uint256 public maxLeverage = 100;
    IPriceOracle public oracle;
    address public owner;
    address public keeper;

    mapping(address => bool) public keepers;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    // ========== VULN 1: Funding Rate Manipulation (PERP-FUND-01) ==========

    // BUG #1: funding rate calculated from OI imbalance—whale opens huge position
    // to skew funding, collects from other side, then closes
    function updateFundingRate(address market) external {
        Market storage m = markets[market];
        uint256 elapsed = block.timestamp - m.lastFundingTime;
        
        // VULN: funding rate directly proportional to OI imbalance
        // whale can push rate to extreme, collect funding, close position
        int256 imbalance = int256(m.longOpenInterest) - int256(m.shortOpenInterest);
        m.fundingRate = (imbalance * 1e18) / int256(m.longOpenInterest + m.shortOpenInterest + 1);
        
        m.cumulativeFundingIndex += uint256(m.fundingRate > 0 ? m.fundingRate : -m.fundingRate) * elapsed / 3600;
        m.lastFundingTime = block.timestamp;
    }

    // ========== VULN 2: Mark Price vs Index Divergence (PERP-MARK-01) ==========

    // BUG #2: mark price uses internal TWAP that can diverge from oracle index
    // enabling arbitrage between perp and spot
    function updateMarkPrice(address market) external {
        Market storage m = markets[market];
        uint256 indexPrice = oracle.getPrice(m.token);
        // VULN: mark price is EMA of internal trades, not oracle
        // can diverge significantly during volatile periods
        m.markPrice = (m.markPrice * 9 + indexPrice) / 10; // slow EMA
        m.indexPrice = indexPrice;
        // Gap between mark and index is exploitable
    }

    // ========== VULN 3: Liquidation Cascade Trigger (PERP-LIQ-01) ==========

    // BUG #3: liquidating large position moves price, triggering more liquidations
    function liquidatePosition(bytes32 posId) external {
        Position storage pos = positions[posId];
        Market storage m = markets[pos.market];
        
        uint256 currentPrice = m.markPrice;
        int256 pnl = _calculatePnL(pos, currentPrice);
        
        uint256 maintenanceMargin = pos.collateral / 20; // 5%
        require(int256(pos.collateral) + pnl <= int256(maintenanceMargin), "not liquidatable");
        
        // VULN: liquidation reduces OI, but market sell moves price further
        // cascading liquidations across all positions
        if (pos.size > 0) {
            m.longOpenInterest -= uint256(pos.size);
        } else {
            m.shortOpenInterest -= uint256(-pos.size);
        }
        
        // Liquidation penalty goes to insurance fund
        uint256 penalty = pos.collateral / 10;
        insuranceFund += penalty;
        
        uint256 remainder = pos.collateral - penalty;
        traderBalances[msg.sender] += remainder; // keeper reward
        
        delete positions[posId];
    }

    // ========== VULN 4: Insurance Fund Drain (PERP-INSURE-01) ==========

    // BUG #4: bad debt from underwater positions eats insurance fund
    // attacker opens max-leverage positions on both sides, one liquidation
    // creates bad debt that drains insurance
    function socializeLoss(uint256 badDebt) external {
        require(keepers[msg.sender], "not keeper");
        // VULN: no rate limiting on insurance fund drains
        // single attack can deplete entire fund
        if (badDebt <= insuranceFund) {
            insuranceFund -= badDebt;
        } else {
            insuranceFund = 0;
            // Remaining bad debt socialized to all traders—unfair
        }
    }

    // ========== VULN 5: Position Size Overflow (PERP-SIZE-01) ==========

    function openPosition(
        address market,
        int256 size,
        uint256 collateral,
        uint256 leverage,
        bool isolated
    ) external returns (bytes32 posId) {
        require(leverage <= maxLeverage, "leverage too high");
        require(collateral > 0, "no collateral");
        
        traderBalances[msg.sender] -= collateral;
        
        Market storage m = markets[market];
        // BUG #5: size * leverage can overflow, creating enormous position with tiny collateral
        uint256 notional = uint256(size > 0 ? size : -size) * leverage;
        // VULN: no notional cap check against actual collateral value
        
        posId = keccak256(abi.encodePacked(msg.sender, market, block.timestamp));
        positions[posId] = Position({
            trader: msg.sender,
            market: market,
            size: size,
            collateral: collateral,
            entryPrice: m.markPrice,
            lastFundingIndex: m.cumulativeFundingIndex,
            isIsolated: isolated,
            leverage: leverage,
            openTimestamp: block.timestamp
        });

        if (size > 0) {
            m.longOpenInterest += uint256(size);
        } else {
            m.shortOpenInterest += uint256(-size);
        }
        
        traderVolume[msg.sender] += notional;
    }

    // ========== VULN 6: Delayed Liquidation Profit (PERP-DELAY-01) ==========

    // BUG #6: keeper waits for position to go deeply underwater
    // liquidation penalty is % of remaining collateral
    // deeper underwater = more penalty = more keeper profit
    function delayedLiquidation(bytes32 posId) external {
        Position storage pos = positions[posId];
        // VULN: no incentive for timely liquidation
        // keeper earns more by waiting, but protocol takes more bad debt
        uint256 keeperReward = pos.collateral / 5; // 20% of remaining
        traderBalances[msg.sender] += keeperReward;
    }

    // ========== VULN 7: Oracle Front-run on Position Open (PERP-ORACLE-01) ==========

    // BUG #7: price used for entry is fetched at execution time
    // MEV bot sees pending openPosition tx, front-runs oracle update
    // victim gets worse entry price
    // (inherent in openPosition using m.markPrice which can be stale)

    // ========== VULN 8: Cross-Margin Contagion (PERP-XMARGIN-01) ==========

    mapping(address => uint256) public crossMarginBalance;

    // BUG #8: cross-margin pools all collateral—loss in one market drains all
    function addCrossMargin(uint256 amount) external {
        traderBalances[msg.sender] -= amount;
        // VULN: cross-margin balance shared across ALL positions
        // one bad trade liquidates everything
        crossMarginBalance[msg.sender] += amount;
    }

    // ========== VULN 9: ADL Priority Manipulation (PERP-ADL-01) ==========

    // BUG #9: Auto-deleverage ranks by profit ratio
    // attacker manipulates profit ratio to avoid ADL selection
    function autoDeleverage(bytes32 posId, bytes32 counterpartyId) external {
        Position storage pos = positions[posId];
        Position storage cp = positions[counterpartyId];
        Market storage m = markets[pos.market];
        
        // VULN: ADL ordering can be gamed by opening hedging positions
        // that reduce apparent profit ratio
        int256 posPnL = _calculatePnL(pos, m.markPrice);
        int256 cpPnL = _calculatePnL(cp, m.markPrice);
        require(cpPnL > 0, "counterparty not profitable");
        
        // Force close profitable position at mark price
        uint256 closeSize = uint256(cp.size > 0 ? cp.size : -cp.size);
        if (cp.size > 0) {
            m.longOpenInterest -= closeSize;
        } else {
            m.shortOpenInterest -= closeSize;
        }
        traderBalances[cp.trader] += cp.collateral + uint256(cpPnL);
        delete positions[counterpartyId];
    }

    // ========== VULN 10: Isolated Margin Escape (PERP-ISO-01) ==========

    // BUG #10: switch from isolated to cross-margin absorbs losses
    function switchToCrossMargin(bytes32 posId) external {
        Position storage pos = positions[posId];
        require(pos.trader == msg.sender, "not owner");
        // VULN: switching to cross-margin when position is underwater
        // cross-margin balance absorbs the unrealized loss
        // effectively doubling down without adding collateral
        pos.isIsolated = false;
    }

    // ========== VULN 11: Leverage Ratchet Attack (PERP-LEV-01) ==========

    // BUG #11: reduce collateral to increase effective leverage beyond max
    function removeCollateral(bytes32 posId, uint256 amount) external {
        Position storage pos = positions[posId];
        require(pos.trader == msg.sender, "not owner");
        pos.collateral -= amount;
        traderBalances[msg.sender] += amount;
        // VULN: no re-check of leverage after collateral removal
        // effective leverage = notional / remaining collateral > maxLeverage
    }

    // ========== VULN 12: Unrealized PnL Withdrawal (PERP-PNL-01) ==========

    // BUG #12: unrealized profit can be withdrawn as collateral
    // if price reverts, position goes underwater with no buffer
    function withdrawUnrealizedProfit(bytes32 posId) external {
        Position storage pos = positions[posId];
        require(pos.trader == msg.sender, "not owner");
        Market storage m = markets[pos.market];
        
        int256 pnl = _calculatePnL(pos, m.markPrice);
        // VULN: allow withdrawal of unrealized PnL
        if (pnl > 0) {
            traderBalances[msg.sender] += uint256(pnl);
            // Position now has no buffer against adverse price movement
        }
    }

    // ========== VULN 13: Stop-Loss Hunting via Spike (PERP-STOPLOSS-01) ==========

    mapping(bytes32 => uint256) public stopLossPrices;

    // BUG #13: whale moves price to trigger clustered stop-losses, creating cascade
    function setStopLoss(bytes32 posId, uint256 stopPrice) external {
        require(positions[posId].trader == msg.sender);
        // VULN: stop-loss prices are public => visible to MEV bots
        // whale pushes price to trigger stops, reverses after cascade
        stopLossPrices[posId] = stopPrice;
    }

    function executeStopLoss(bytes32 posId) external {
        require(keepers[msg.sender], "not keeper");
        Position storage pos = positions[posId];
        Market storage m = markets[pos.market];
        // VULN: execution at market price after spike, not stop price
        require(m.markPrice <= stopLossPrices[posId], "stop not triggered");
        // Close at current (worst) price, not stop price
        _closePosition(posId, m.markPrice);
    }

    // ========== VULN 14: Max Open Interest Bypass (PERP-OI-01) ==========

    // BUG #14: OI check only on open, not on funding rate update
    // positions that receive funding effectively increase their size
    function checkOI(address market) external view returns (bool) {
        Market storage m = markets[market];
        // VULN: doesn't account for funding accrual increasing effective OI
        return m.longOpenInterest + m.shortOpenInterest <= m.maxOpenInterest;
    }

    // ========== VULN 15: Fee Tier Manipulation (PERP-FEETIER-01) ==========

    // BUG #15: volume-based fee tiers => wash trading to reach lower tier
    function getFeeTier(address trader) public view returns (uint256) {
        uint256 vol = traderVolume[trader];
        // VULN: volume includes self-trades and wash trades
        // attacker opens/closes at same price to inflate volume for 0 cost
        if (vol > 1000000e18) return 1; // VIP: 0.01%
        if (vol > 100000e18) return 5;  // Pro: 0.05%
        return 10; // Retail: 0.1%
    }

    // ========== VULN 16: Late Close Penalty Avoidance (PERP-LATECLOSE-01) ==========

    // BUG #16: position can be transferred to avoid late-close penalties
    function transferPosition(bytes32 posId, address newTrader) external {
        Position storage pos = positions[posId];
        require(pos.trader == msg.sender);
        // VULN: transfer resets accountability, new "trader" has clean history
        pos.trader = newTrader;
    }

    // ========== VULN 17: Partial Liquidation Gaming (PERP-PARTLIQ-01) ==========

    // BUG #17: partial liquidation closes minimum to restore margin
    // attacker repeatedly goes to edge of liquidation then adds tiny collateral
    function partialLiquidation(bytes32 posId, uint256 closePercent) external {
        require(keepers[msg.sender], "not keeper");
        Position storage pos = positions[posId];
        // VULN: closePercent chosen by keeper, not protocol
        // keeper closes maximum for maximum reward
        uint256 closedSize = uint256(pos.size > 0 ? pos.size : -pos.size) * closePercent / 100;
        pos.collateral -= pos.collateral * closePercent / 100;
        if (pos.size > 0) {
            pos.size -= int256(closedSize);
        } else {
            pos.size += int256(closedSize);
        }
    }

    // ========== VULN 18: Keeper Bot Incentive Theft (PERP-KEEPER-01) ==========

    // BUG #18: keeper reward is flat fee, not proportional to risk
    // keeper can grief small positions where reward > remaining collateral
    function keeperReward(bytes32 posId) external view returns (uint256) {
        Position storage pos = positions[posId];
        // VULN: flat 0.1 ETH reward even for positions with 0.05 ETH collateral
        // creates bad debt for small positions
        return 0.1 ether;
    }

    // ========== VULN 19: Funding Accrual Timestamp Gaming (PERP-TIMESTAMP-01) ==========

    // BUG #19: funding calculated per-hour, but miners control timestamp
    // funding update can be gamed by controlling block.timestamp
    function accruePositionFunding(bytes32 posId) external {
        Position storage pos = positions[posId];
        Market storage m = markets[pos.market];
        
        uint256 fundingDelta = m.cumulativeFundingIndex - pos.lastFundingIndex;
        // VULN: timestamp manipulation changes elapsed hours
        // miner/sequencer can delay or advance funding accrual
        int256 fundingPayment = int256(fundingDelta) * pos.size / 1e18;
        
        if (fundingPayment > 0) {
            pos.collateral -= uint256(fundingPayment);
        } else {
            pos.collateral += uint256(-fundingPayment);
        }
        pos.lastFundingIndex = m.cumulativeFundingIndex;
    }

    // ========== VULN 20: Settlement Price Manipulation (PERP-SETTLE-01) ==========

    mapping(address => uint256) public settlementPrices;
    mapping(address => bool) public settled;

    // BUG #20: perpetual market settlement (if market is delisted)
    // uses single oracle read that can be manipulated
    function settleMarket(address market) external {
        require(msg.sender == owner, "only owner");
        // VULN: settlement at single point-in-time price, manipulable
        settlementPrices[market] = oracle.getPrice(markets[market].token);
        settled[market] = true;
    }

    function claimSettlement(bytes32 posId) external {
        Position storage pos = positions[posId];
        require(settled[pos.market], "not settled");
        // Uses potentially manipulated settlement price
        int256 pnl = _calculatePnL(pos, settlementPrices[pos.market]);
        uint256 payout = uint256(int256(pos.collateral) + pnl);
        traderBalances[pos.trader] += payout;
        delete positions[posId];
    }

    // ========== Internal Helpers ==========

    function _calculatePnL(Position storage pos, uint256 currentPrice) internal view returns (int256) {
        if (pos.size > 0) {
            return int256((currentPrice - pos.entryPrice) * uint256(pos.size) / pos.entryPrice);
        } else {
            return int256((pos.entryPrice - currentPrice) * uint256(-pos.size) / pos.entryPrice);
        }
    }

    function _closePosition(bytes32 posId, uint256 price) internal {
        Position storage pos = positions[posId];
        Market storage m = markets[pos.market];
        int256 pnl = _calculatePnL(pos, price);
        
        if (pos.size > 0) {
            m.longOpenInterest -= uint256(pos.size);
        } else {
            m.shortOpenInterest -= uint256(-pos.size);
        }
        
        uint256 payout = uint256(int256(pos.collateral) + pnl);
        traderBalances[pos.trader] += payout;
        delete positions[posId];
    }

    // Admin
    function addKeeper(address k) external { require(msg.sender == owner); keepers[k] = true; }
    function initMarket(address token, uint256 maxOI) external {
        require(msg.sender == owner);
        markets[token] = Market({
            token: token,
            fundingRate: 0,
            longOpenInterest: 0,
            shortOpenInterest: 0,
            maxOpenInterest: maxOI,
            lastFundingTime: block.timestamp,
            cumulativeFundingIndex: 0,
            markPrice: oracle.getPrice(token),
            indexPrice: oracle.getPrice(token)
        });
    }

    function depositBalance() external payable {
        traderBalances[msg.sender] += msg.value;
    }
}
