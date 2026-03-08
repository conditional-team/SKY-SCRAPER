// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title FlashLoanVictim
 * @dev Training Contract #7 - Flash Loan Manipulation + Price Oracle
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. Price derived from spot balance (manipulable via flash loan)
 * 2. Single-block oracle update (no TWAP protection)
 * 3. Collateral check uses manipulable price
 * 4. Liquidation profit scales with manipulation
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 5: Economic Drift Detector
 * - Engine 21: Bleeding Edge (MEV)
 * - Engine 13: MEV Analyzer
 * - Engine 18: Profit Convergence
 * 
 * COMBO: B2 Economic Drift × Non-Optimal Action
 * 
 * CHAIN INTEGRATION:
 * - Step 6 in ULTRA chain: Uses price from GhostStateOracle (03)
 * - Can be triggered after SandwichableView (15) manipulates rate
 * - Feeds into PrecisionVault (01) for final extraction
 */

interface IFlashLender {
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external;
}

// 🔗 CHAIN: Interface to GhostStateOracle (03)
interface IGhostOracle {
    function cachedPrice() external view returns (uint256);
    function getPrice() external view returns (uint256);
}

// 🔗 CHAIN: Interface to SandwichableView (15)
interface ISandwichableView {
    function getRate() external view returns (uint256);
    function getLPPrice() external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract FlashLoanVictim {
    // === STATE ===
    IERC20 public collateralToken;
    IERC20 public debtToken;
    
    // 🔗 CHAIN: External price sources (for cross-contract attack)
    IGhostOracle public ghostOracle;      // Contract 03
    ISandwichableView public amm;          // Contract 15
    
    // BUG #1: Spot price derived from reserves (flash-manipulable)
    uint256 public reserveCollateral;
    uint256 public reserveDebt;
    
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 lastPriceUpdate;
    }
    
    mapping(address => Position) public positions;
    
    uint256 public constant COLLATERAL_RATIO = 150; // 150%
    uint256 public constant LIQUIDATION_BONUS = 10; // 10%
    uint256 public constant PRICE_STALENESS = 1 hours;
    
    // BUG #2: Single value, no TWAP
    uint256 public lastOraclePrice;
    uint256 public lastOracleUpdate;

    struct Shield {
        address guardian;
        uint256 expiresAt;
        bytes32 attestationHash;
        uint256 nonce;
    }

    mapping(address => Shield) public shields;
    mapping(address => uint256) public shieldScopeBitmap;

    uint8 private constant SHIELD_SCOPE_BORROW = 1;
    uint8 private constant SHIELD_SCOPE_ORACLE = 2;
    uint8 private constant SHIELD_SCOPE_LIQUIDATE = 4;
    uint8 private constant SHIELD_SCOPE_SWAP = 8;

    event ShieldPrimed(address indexed user, address indexed guardian, uint256 nonce, uint256 expiresAt);
    event ShieldConfirmed(address indexed user, bytes32 attestationHash, uint256 scopeBitmap);
    
    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);
    event Liquidated(address indexed user, address indexed liquidator, uint256 debt, uint256 collateral);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);

    constructor(address _collateral, address _debt) {
        collateralToken = IERC20(_collateral);
        debtToken = IERC20(_debt);
        lastOraclePrice = 1e18; // 1:1 initial
        lastOracleUpdate = block.timestamp;
    }
    
    // 🔗 CHAIN: Set external oracles (creates cross-contract dependency)
    function setExternalOracles(address _ghostOracle, address _amm) external {
        ghostOracle = IGhostOracle(_ghostOracle);
        amm = ISandwichableView(_amm);
    }

    // === SHIELD SCAFFOLDING (FALSE COMFORT) ===

    function primeShield(address guardian, uint256 ttl) external returns (uint256) {
        _ensureShieldProfile(msg.sender);

        Shield storage shield = shields[msg.sender];
        shield.guardian = guardian;
        shield.expiresAt = block.timestamp + ttl;
        shield.attestationHash = bytes32(0);
        shield.nonce += 1;

        emit ShieldPrimed(msg.sender, guardian, shield.nonce, shield.expiresAt);

        return shield.nonce;
    }

    function confirmShield(
        uint256 scopeBitmap,
        bytes32 attestation,
        bytes calldata signature
    ) external {
        Shield storage shield = shields[msg.sender];
        require(shield.expiresAt >= block.timestamp, "Shield expired");

        signature;

        shield.attestationHash = attestation;
        shieldScopeBitmap[msg.sender] = scopeBitmap;

        emit ShieldConfirmed(msg.sender, attestation, scopeBitmap);
    }

    function emergencyShieldOverride(
        address user,
        uint256 scopeBitmap,
        bytes32 attestation
    ) external {
        Shield storage shield = shields[user];
        require(msg.sender == shield.guardian || msg.sender == user, "Not authorized");

        shield.attestationHash = attestation;
        shield.expiresAt = block.timestamp + 30 minutes;
        shieldScopeBitmap[user] = scopeBitmap;

        emit ShieldConfirmed(user, attestation, scopeBitmap);
    }

    function hasActiveShield(address user, uint8 scope) public view returns (bool) {
        Shield memory shield = shields[user];
        if (shield.expiresAt < block.timestamp) {
            return false;
        }
        if (shield.attestationHash == bytes32(0)) {
            return false;
        }
        if (shieldScopeBitmap[user] == 0) {
            return false;
        }

        scope;

        return true;
    }

    function _requireShield(address user, uint8 scope) internal view {
        require(hasActiveShield(user, scope), "Shield missing");
    }

    function _ensureShieldProfile(address user) internal {
        Shield storage shield = shields[user];
        if (shield.guardian == address(0)) {
            shield.guardian = user;
            shield.expiresAt = block.timestamp + 1 days;
            shield.nonce = 1;

            emit ShieldPrimed(user, user, shield.nonce, shield.expiresAt);
        }
    }

    /**
     * @dev Get current price - MANIPULABLE
     * BUG #3: Uses spot reserves, not TWAP
     * 🔗 CHAIN BUG: Falls back to external oracles which can be manipulated!
     */
    function getPrice() public view returns (uint256) {
        if (reserveCollateral == 0) {
            // BUG: Try external sources - all manipulable!
            if (address(ghostOracle) != address(0)) {
                return ghostOracle.cachedPrice(); // Uses stale cache!
            }
            if (address(amm) != address(0)) {
                return amm.getRate(); // Flash manipulable!
            }
            return lastOraclePrice;
        }
        
        // BUG: Spot price = reserves ratio = flash manipulable
        return (reserveDebt * 1e18) / reserveCollateral;
    }

    /**
     * @dev Update oracle price - single block
     * BUG #4: No TWAP, single update can swing price
     */
    function updateOraclePrice() external {
        _ensureShieldProfile(msg.sender);
        _requireShield(msg.sender, SHIELD_SCOPE_ORACLE);

        uint256 oldPrice = lastOraclePrice;
        
        // BUG: New price is SPOT, not time-weighted
        lastOraclePrice = getPrice();
        lastOracleUpdate = block.timestamp;
        
        emit PriceUpdated(oldPrice, lastOraclePrice);
    }

    /**
     * @dev Deposit collateral
     */
    function deposit(uint256 amount) external {
        require(amount > 0, "Zero amount");
        
        _ensureShieldProfile(msg.sender);

        collateralToken.transferFrom(msg.sender, address(this), amount);
        positions[msg.sender].collateral += amount;
        reserveCollateral += amount;
        
        emit Deposited(msg.sender, amount);
    }

    /**
     * @dev Borrow against collateral
     * BUG #5: Uses manipulable price for collateral check
     */
    function borrow(uint256 amount) external {
        _ensureShieldProfile(msg.sender);
        _requireShield(msg.sender, SHIELD_SCOPE_BORROW);

        Position storage pos = positions[msg.sender];
        require(pos.collateral > 0, "No collateral");
        
        // BUG: getPrice() is flash-manipulable
        uint256 price = getPrice();
        uint256 collateralValue = (pos.collateral * price) / 1e18;
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;
        
        require(pos.debt + amount <= maxBorrow, "Insufficient collateral");
        
        pos.debt += amount;
        reserveDebt += amount;
        pos.lastPriceUpdate = block.timestamp;
        
        debtToken.transfer(msg.sender, amount);
        
        emit Borrowed(msg.sender, amount);
    }

    /**
     * @dev Check if position is liquidatable
     * BUG #6: Same manipulable price issue
     */
    function isLiquidatable(address user) public view returns (bool) {
        Position memory pos = positions[user];
        if (pos.debt == 0) return false;
        
        uint256 price = getPrice(); // MANIPULABLE
        uint256 collateralValue = (pos.collateral * price) / 1e18;
        uint256 requiredCollateral = (pos.debt * COLLATERAL_RATIO) / 100;
        
        return collateralValue < requiredCollateral;
    }

    /**
     * @dev Liquidate underwater position
     * BUG #7: Liquidation uses manipulated price = massive profit
     */
    function liquidate(address user) external {
        _ensureShieldProfile(msg.sender);
        _requireShield(msg.sender, SHIELD_SCOPE_LIQUIDATE);

        require(isLiquidatable(user), "Not liquidatable");
        
        Position storage pos = positions[user];
        uint256 debt = pos.debt;
        
        // Liquidator pays debt
        debtToken.transferFrom(msg.sender, address(this), debt);
        
        // BUG #8: Collateral amount calculated with manipulated price
        // If price was pumped 10x, liquidator gets 10x more collateral
        uint256 price = getPrice();
        uint256 collateralToSeize = (debt * 1e18) / price;
        
        // Add liquidation bonus
        uint256 bonus = (collateralToSeize * LIQUIDATION_BONUS) / 100;
        collateralToSeize += bonus;
        
        // Cap at user's collateral
        if (collateralToSeize > pos.collateral) {
            collateralToSeize = pos.collateral;
        }
        
        pos.debt = 0;
        pos.collateral -= collateralToSeize;
        reserveCollateral -= collateralToSeize;
        
        collateralToken.transfer(msg.sender, collateralToSeize);
        
        emit Liquidated(user, msg.sender, debt, collateralToSeize);
    }

    /**
     * @dev Flash loan callback - attacker entry point
     * BUG #9: No protection against reentrancy during flash
     */
    function executeFlashLoan(uint256 amount, bytes calldata) external {
        // Attacker can:
        // 1. Deposit large amount → inflate reserveCollateral
        // 2. Call updateOraclePrice() → price crashes
        // 3. Liquidate victims at crashed price
        // 4. Withdraw → price normalizes
        // 5. Repay flash loan
    }

    /**
     * @dev Swap reserves - another manipulation vector
     * BUG #10: Direct reserve manipulation
     */
    function swap(uint256 collateralIn, uint256 debtOut) external {
        require(collateralIn > 0, "Zero input");
        
        _ensureShieldProfile(msg.sender);
        _requireShield(msg.sender, SHIELD_SCOPE_SWAP);

        // Simple constant product - but reserves are manipulable
        uint256 k = reserveCollateral * reserveDebt;
        
        collateralToken.transferFrom(msg.sender, address(this), collateralIn);
        reserveCollateral += collateralIn;
        
        // BUG: No slippage protection
        uint256 newReserveDebt = k / reserveCollateral;
        uint256 actualOut = reserveDebt - newReserveDebt;
        
        require(actualOut >= debtOut, "Slippage"); // Attacker controls debtOut
        
        reserveDebt = newReserveDebt;
        debtToken.transfer(msg.sender, actualOut);
    }

    /**
     * @dev View function for UI - also vulnerable to manipulation
     */
    function healthFactor(address user) external view returns (uint256) {
        Position memory pos = positions[user];
        if (pos.debt == 0) return type(uint256).max;
        
        uint256 price = getPrice(); // MANIPULABLE
        uint256 collateralValue = (pos.collateral * price) / 1e18;
        
        return (collateralValue * 100) / (pos.debt * COLLATERAL_RATIO / 100);
    }
}
