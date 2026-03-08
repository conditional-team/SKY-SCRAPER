// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title StablecoinDepeg
 * @dev Training Contract #49 - Stablecoin Depeg & PSM Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. PSM Redemption Front-run (STABLE-PSM-01)
 * 2. PSM Fee Bypass via Flash Mint (STABLE-PSM-02)
 * 3. Depeg Oracle Mismatch (STABLE-DEPEG-01)
 * 4. Bank-Run Cascade (STABLE-BANKRUN-01)
 * 5. Curve Pool Imbalance Exploit (STABLE-CURVE-01)
 * 6. Collateral Ratio Manipulation (STABLE-CR-01)
 * 7. Algorithmic Mint Spiral (STABLE-ALGO-01)
 * 8. Governance Token Dump Cascade (STABLE-GOV-01)
 * 9. Liquidation Threshold Stacking (STABLE-LIQTHRESH-01)
 * 10. Bad Debt Accumulation (STABLE-BADDEBT-01)
 * 11. Keeper Under-collateralization (STABLE-KEEPERUSC-01)
 * 12. Flash Mint Arbitrage Loop (STABLE-FLASHMINT-01)
 * 13. Multi-Collateral Contagion (STABLE-MULTICOL-01)
 * 14. Interest Rate Oracle Gaming (STABLE-RATE-01)
 * 15. Emergency Shutdown Race (STABLE-SHUTDOWN-01)
 * 16. Partial Reserve Proof Fake (STABLE-RESERVE-01)
 * 17. Rebasing Stablecoin Desync (STABLE-REBASE-01)
 * 18. Cross-Chain Peg Arbitrage (STABLE-XCHAIN-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): STABLE-*, PSM, depeg, bank-run
 * - Engine 2 (deep-semantic): collateral ratio, mint/burn logic
 * - Engine 3 (state-desync): oracle mismatch, rate desync
 * - Engine 13 (mev-analyzer): front-run, arbitrage loop, flash mint
 */

interface IERC20Stable {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function mint(address, uint256) external;
    function burn(address, uint256) external;
    function totalSupply() external view returns (uint256);
}

interface IStableOracle {
    function getPrice(address) external view returns (uint256);
    function getDecimals(address) external view returns (uint8);
}

// ========== VULN 1: PSM Redemption Front-run (STABLE-PSM-01) ==========
// ========== VULN 2: PSM Fee Bypass via Flash Mint (STABLE-PSM-02) ==========

contract PegStabilityModule {
    IERC20Stable public stablecoin;
    IERC20Stable public reserveAsset; // USDC
    uint256 public mintFee = 10;  // 0.1%
    uint256 public redeemFee = 10;
    uint256 public totalReserves;
    uint256 public debtCeiling = 100_000_000e18;
    uint256 public totalDebt;
    address public owner;

    constructor(address _stable, address _reserve) {
        stablecoin = IERC20Stable(_stable);
        reserveAsset = IERC20Stable(_reserve);
        owner = msg.sender;
    }

    // BUG #1: PSM mint/redeem is front-runnable
    // attacker sees large redemption in mempool, redeems first at 1:1
    // then victim redeems at worse rate due to depleted reserves
    function mint(uint256 reserveAmount) external returns (uint256 stableOut) {
        reserveAsset.transferFrom(msg.sender, address(this), reserveAmount);
        // VULN: no slippage protection, no reserve minimum check
        uint256 fee = reserveAmount * mintFee / 10000;
        stableOut = reserveAmount - fee;
        require(totalDebt + stableOut <= debtCeiling, "ceiling");
        totalDebt += stableOut;
        totalReserves += reserveAmount;
        stablecoin.mint(msg.sender, stableOut);
    }

    // BUG #2: flash mint → redeem in same tx bypasses fee
    // mint with USDC → get stablecoin → redeem immediately → profit from rounding
    function redeem(uint256 stableAmount) external returns (uint256 reserveOut) {
        stablecoin.burn(msg.sender, stableAmount);
        uint256 fee = stableAmount * redeemFee / 10000;
        reserveOut = stableAmount - fee;
        // VULN: no check that minter != redeemer in same tx
        // flash mint attack: deposit USDC → mint stable → redeem stable → get more USDC
        require(reserveOut <= totalReserves, "insufficient reserves");
        totalReserves -= reserveOut;
        totalDebt -= stableAmount;
        reserveAsset.transfer(msg.sender, reserveOut);
    }

    function setFees(uint256 _mint, uint256 _redeem) external {
        require(msg.sender == owner);
        // No cap on fees
        mintFee = _mint;
        redeemFee = _redeem;
    }
}

// ========== VULN 3: Depeg Oracle Mismatch (STABLE-DEPEG-01) ==========

contract DepegOracle {
    mapping(address => uint256) public prices;
    mapping(address => uint256) public lastUpdate;
    address public updater;
    uint256 public constant PEG = 1e18; // $1.00

    constructor() { updater = msg.sender; }

    // BUG #3: oracle still reports $1.00 while market trades at $0.85
    // lending protocols use this stale price, enabling over-borrowing
    function updatePrice(address token, uint256 price) external {
        require(msg.sender == updater);
        // VULN: no deviation check from peg, no heartbeat requirement
        // can report $1.00 indefinitely even during depeg
        prices[token] = price;
        lastUpdate[token] = block.timestamp;
    }

    function getPrice(address token) external view returns (uint256) {
        // VULN: no staleness check, returns last reported price
        return prices[token];
    }
}

// ========== VULN 4: Bank-Run Cascade (STABLE-BANKRUN-01) ==========

contract StablecoinVault {
    IERC20Stable public stablecoin;
    IStableOracle public oracle;
    
    struct CDP {
        address owner;
        address collateral;
        uint256 collateralAmount;
        uint256 debtAmount;
        uint256 lastInterest;
    }

    mapping(uint256 => CDP) public cdps;
    uint256 public nextCdpId;
    uint256 public totalSystemDebt;
    uint256 public collateralizationRatio = 150; // 150%
    uint256 public liquidationRatio = 110; // 110%
    mapping(address => uint256) public stabilityPool; // depositors
    uint256 public totalStabilityPool;
    address public owner;

    // Algorithmic parameters
    uint256 public govTokenPrice = 1e18;
    IERC20Stable public govToken;
    uint256 public interestRate = 500; // 5% annual
    bool public emergencyShutdown;

    constructor(address _stable, address _oracle, address _gov) {
        stablecoin = IERC20Stable(_stable);
        oracle = IStableOracle(_oracle);
        govToken = IERC20Stable(_gov);
        owner = msg.sender;
    }

    // BUG #4: when users rush to close CDPs, stability pool drains
    // remaining CDPs become under-collateralized => more bank-run
    function openCDP(address collateral, uint256 colAmount, uint256 mintAmount) external returns (uint256 cdpId) {
        uint256 colValue = oracle.getPrice(collateral) * colAmount / 1e18;
        require(colValue * 100 / mintAmount >= collateralizationRatio, "under-col");
        
        IERC20Stable(collateral).transferFrom(msg.sender, address(this), colAmount);
        
        cdpId = nextCdpId++;
        cdps[cdpId] = CDP({
            owner: msg.sender,
            collateral: collateral,
            collateralAmount: colAmount,
            debtAmount: mintAmount,
            lastInterest: block.timestamp
        });
        totalSystemDebt += mintAmount;
        stablecoin.mint(msg.sender, mintAmount);
    }

    // VULN: mass redemption path has no rate limiting
    function closeCDP(uint256 cdpId) external {
        CDP storage cdp = cdps[cdpId];
        require(cdp.owner == msg.sender, "not owner");
        stablecoin.burn(msg.sender, cdp.debtAmount);
        totalSystemDebt -= cdp.debtAmount;
        IERC20Stable(cdp.collateral).transfer(msg.sender, cdp.collateralAmount);
        delete cdps[cdpId];
    }

    // ========== VULN 5: Curve Pool Imbalance Exploit (STABLE-CURVE-01) ==========

    mapping(address => uint256) public poolBalances;

    // BUG #5: stablecoin's Curve pool balance used as price oracle
    // attacker imbalances pool to manipulate perceived price
    function getCurveImpliedPrice() public view returns (uint256) {
        uint256 stableBalance = poolBalances[address(stablecoin)];
        uint256 usdcBalance = poolBalances[address(0x1)]; // USDC placeholder
        // VULN: price derived from pool ratio, manipulable in single tx
        if (stableBalance == 0) return 1e18;
        return (usdcBalance * 1e18) / stableBalance;
    }

    // ========== VULN 6: Collateral Ratio Manipulation (STABLE-CR-01) ==========

    // BUG #6: collateral ratio check uses spot oracle price
    // flash loan → pump collateral price → open CDP → dump price
    function addCollateral(uint256 cdpId, uint256 amount) external {
        CDP storage cdp = cdps[cdpId];
        IERC20Stable(cdp.collateral).transferFrom(msg.sender, address(this), amount);
        // VULN: no TWAP, spot price manipulable
        cdp.collateralAmount += amount;
    }

    // ========== VULN 7: Algorithmic Mint Spiral (STABLE-ALGO-01) ==========

    // BUG #7: when stable depegs below $1, protocol mints gov tokens to buy back
    // more selling pressure on gov token => less buyback power => death spiral
    function algorithmicStabilize(uint256 amount) external {
        require(getCurveImpliedPrice() < 0.99e18, "no depeg");
        // VULN: minting gov tokens during depeg accelerates spiral
        // each mint dilutes gov token => price falls further => need more mints
        uint256 govMintAmount = (amount * 1e18) / govTokenPrice;
        govToken.mint(msg.sender, govMintAmount);
        // Expectation: user sells gov token for stablecoin to restore peg
        // Reality: selling gov token crashes its price => spiral
    }

    // ========== VULN 8: Governance Token Dump Cascade (STABLE-GOV-01) ==========

    // BUG #8: gov token holders can dump during depeg before backstop kicks in
    function sellGovForStable(uint256 govAmount) external {
        govToken.burn(msg.sender, govAmount);
        uint256 stableOut = govAmount * govTokenPrice / 1e18;
        // VULN: uses stale govTokenPrice, not market price
        // dumpers get favorable rate while token is crashing
        stablecoin.mint(msg.sender, stableOut);
        totalSystemDebt += stableOut;
    }

    // ========== VULN 9: Liquidation Threshold Stacking (STABLE-LIQTHRESH-01) ==========

    // BUG #9: multiple CDPs from same address at different thresholds
    // when price drops, all liquidate simultaneously, overwhelming stability pool
    function batchLiquidate(uint256[] calldata cdpIds) external {
        for (uint256 i = 0; i < cdpIds.length; i++) {
            CDP storage cdp = cdps[cdpIds[i]];
            uint256 colValue = oracle.getPrice(cdp.collateral) * cdp.collateralAmount / 1e18;
            uint256 ratio = colValue * 100 / cdp.debtAmount;
            
            if (ratio < liquidationRatio) {
                // VULN: no limit on simultaneous liquidations
                // stability pool can be drained in one tx
                uint256 debtToRepay = cdp.debtAmount;
                if (debtToRepay <= totalStabilityPool) {
                    totalStabilityPool -= debtToRepay;
                }
                totalSystemDebt -= cdp.debtAmount;
                delete cdps[cdpIds[i]];
            }
        }
    }

    // ========== VULN 10: Bad Debt Accumulation (STABLE-BADDEBT-01) ==========

    uint256 public systemBadDebt;

    // BUG #10: underwater CDPs create bad debt that's never resolved
    // system-wide undercollateralization creeps up over time
    function recordBadDebt(uint256 cdpId) external {
        CDP storage cdp = cdps[cdpId];
        uint256 colValue = oracle.getPrice(cdp.collateral) * cdp.collateralAmount / 1e18;
        if (colValue < cdp.debtAmount) {
            // VULN: bad debt tracked but never repaid
            // stablecoin becomes increasingly un-backed
            systemBadDebt += cdp.debtAmount - colValue;
        }
    }

    // ========== VULN 11: Keeper Under-collateralization (STABLE-KEEPERUSC-01) ==========

    // BUG #11: keeper liquidation reward comes from collateral
    // if collateral < debt + reward, system subsidizes keeper from protocol funds
    function liquidateWithReward(uint256 cdpId) external {
        CDP storage cdp = cdps[cdpId];
        uint256 colValue = oracle.getPrice(cdp.collateral) * cdp.collateralAmount / 1e18;
        uint256 ratio = colValue * 100 / cdp.debtAmount;
        require(ratio < liquidationRatio, "safe");
        
        // VULN: keeper reward (5%) may exceed available collateral
        uint256 reward = cdp.collateralAmount * 5 / 100;
        uint256 remainder = cdp.collateralAmount - reward;
        IERC20Stable(cdp.collateral).transfer(msg.sender, reward);
        // remainder may not cover debt => bad debt
        totalSystemDebt -= cdp.debtAmount;
        delete cdps[cdpId];
    }

    // ========== VULN 12: Flash Mint Arbitrage Loop (STABLE-FLASHMINT-01) ==========

    // BUG #12: protocol offers flash mint of stablecoins
    // attacker flash mints → sells on DEX → depegs → buys cheap → repays
    function flashMint(uint256 amount, bytes calldata data) external {
        // VULN: flash mint has no fee, enables free depeg attack
        stablecoin.mint(msg.sender, amount);
        // Borrower uses stablecoins (sells on DEX, depresses price)
        (bool ok, ) = msg.sender.call(data);
        require(ok, "callback failed");
        // Borrower should return stablecoins
        stablecoin.burn(msg.sender, amount);
        // But they already profited from the depeg they caused
    }

    // ========== VULN 13: Multi-Collateral Contagion (STABLE-MULTICOL-01) ==========

    mapping(address => bool) public acceptedCollateral;

    // BUG #13: if one collateral type depegs, CDPs backed by it become underwater
    // system tries to auction bad collateral, floods market, crashes other collaterals too
    function addAcceptedCollateral(address token) external {
        require(msg.sender == owner);
        // VULN: no correlation check between collateral types  
        // correlated assets (e.g., stETH + rETH) fail simultaneously
        acceptedCollateral[token] = true;
    }

    // ========== VULN 14: Interest Rate Oracle Gaming (STABLE-RATE-01) ==========

    // BUG #14: stability fee (interest rate) set by governance with delay
    // insiders front-run rate changes: borrow before rate drop, repay before rate hike
    function updateInterestRate(uint256 newRate) external {
        require(msg.sender == owner);
        // VULN: no timelock, immediate effect, insiders see governance tx
        interestRate = newRate;
    }

    function accrueInterest(uint256 cdpId) external {
        CDP storage cdp = cdps[cdpId];
        uint256 elapsed = block.timestamp - cdp.lastInterest;
        uint256 interest = cdp.debtAmount * interestRate * elapsed / (10000 * 365 days);
        cdp.debtAmount += interest;
        totalSystemDebt += interest;
        cdp.lastInterest = block.timestamp;
    }

    // ========== VULN 15: Emergency Shutdown Race (STABLE-SHUTDOWN-01) ==========

    mapping(address => uint256) public shutdownClaims;

    // BUG #15: emergency shutdown freezes all CDPs at current prices
    // insiders front-run shutdown announcement to dump stablecoins
    function triggerShutdown() external {
        require(msg.sender == owner);
        // VULN: no timelock, instant effect
        emergencyShutdown = true;
    }

    function claimCollateralAfterShutdown(uint256 cdpId) external {
        require(emergencyShutdown, "not shutdown");
        CDP storage cdp = cdps[cdpId];
        // VULN: claims at shutdown price, which may be manipulated
        // insiders know shutdown is coming, position accordingly
        uint256 entitlement = cdp.collateralAmount * cdp.debtAmount / totalSystemDebt;
        IERC20Stable(cdp.collateral).transfer(cdp.owner, entitlement);
        delete cdps[cdpId];
    }

    // ========== VULN 16: Partial Reserve Proof Fake (STABLE-RESERVE-01) ==========

    mapping(address => uint256) public reportedReserves;

    // BUG #16: reserve proof is self-reported, not verifiable on-chain
    function reportReserves(address asset, uint256 amount) external {
        require(msg.sender == owner);
        // VULN: owner can report any reserve amount
        // actual reserves may be lower → fractional reserve stablecoin
        reportedReserves[asset] = amount;
    }

    function getReserveRatio() external view returns (uint256) {
        uint256 totalReserveValue;
        // Just returns self-reported numbers—no verification
        return (totalReserveValue * 100) / (totalSystemDebt + 1);
    }

    // ========== VULN 17: Rebasing Stablecoin Desync (STABLE-REBASE-01) ==========

    uint256 public rebaseIndex = 1e18;

    // BUG #17: rebasing stablecoin's balance changes break DeFi integrations
    // lending protocol caches balance, then rebase changes it → accounting drift
    function rebase(uint256 newIndex) external {
        require(msg.sender == owner);
        // VULN: external protocols don't handle rebase events
        // Aave/Compound balance vs actual balance diverges
        rebaseIndex = newIndex;
    }

    function balanceOfUnderlying(address user) external view returns (uint256) {
        return stabilityPool[user] * rebaseIndex / 1e18;
    }

    // ========== VULN 18: Cross-Chain Peg Arbitrage (STABLE-XCHAIN-01) ==========

    mapping(uint256 => uint256) public chainBridgeLimits;

    // BUG #18: stablecoin trades at different prices on different chains
    // bridge delay creates arb window during depeg events
    function bridgeToChain(uint256 chainId, uint256 amount) external {
        require(amount <= chainBridgeLimits[chainId], "over limit");
        stablecoin.burn(msg.sender, amount);
        // VULN: message sent to bridge, tokens minted on destination
        // if source chain depegs, destination still mints at 1:1
        // attacker bridges from depegged chain to healthy chain
    }

    // Stability pool
    function depositToStabilityPool(uint256 amount) external {
        stablecoin.transferFrom(msg.sender, address(this), amount);
        stabilityPool[msg.sender] += amount;
        totalStabilityPool += amount;
    }

    function setChainLimit(uint256 chainId, uint256 limit) external {
        require(msg.sender == owner);
        chainBridgeLimits[chainId] = limit;
    }
}
