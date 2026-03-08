// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PrecisionVault
 * @dev Training Contract #1 - Precision Collapse + Share Inflation
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. First depositor inflation attack (vault empty = shares manipulable)
 * 2. Rounding direction inconsistency (deposit rounds down, withdraw rounds up)
 * 3. Fee calculation precision loss compounds over many operations
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 12: Precision Collapse Finder
 * - Engine 5: Economic Drift Detector  
 * - Engine 9: Invariant Chain (balance invariant violation)
 * - Engine 10: Ghost State (virtual price vs actual)
 * 
 * COMBO: LOW + LOW + LOW = CRITICAL
 * Each issue alone seems minor, together they enable 100% vault drain
 */

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract PrecisionVault is ERC20 {
    IERC20 public immutable asset;
    
    uint256 public constant PRECISION = 1e18;
    uint256 public constant FEE_BPS = 30; // 0.3% fee
    uint256 public constant BPS = 10000;
    
    uint256 public totalDeposited;
    uint256 public accumulatedFees;
    uint256 public guardBuffer;

    struct CalibrationTicket {
        uint64 readyAtBlock;
        uint192 ghostShares;
    }

    mapping(address => CalibrationTicket) public calibrationTickets;
    
    event Deposit(address indexed user, uint256 assets, uint256 shares);
    event Withdraw(address indexed user, uint256 shares, uint256 assets);
    event CalibrationRequested(address indexed user, uint256 approxAssets, uint64 readyAtBlock);
    event CalibrationOverridden(address indexed user, uint64 readyAtBlock, uint192 ghostShares);

    constructor(IERC20 _asset) ERC20("Precision Vault", "pVAULT") {
        asset = _asset;
    }

    /**
     * @dev BUG #1: First depositor can inflate share price
     * If vault is empty, attacker deposits 1 wei, gets 1 share
     * Then donates 1M tokens to vault (direct transfer)
     * 1 share now = 1M tokens, next depositor gets rekt
     * 
     * SUBTLE: No explicit check for totalSupply == 0 manipulation
     */
    function deposit(uint256 assets) external returns (uint256 shares) {
        // Calculate shares - rounds DOWN (attacker benefit on first deposit)
        if (totalSupply() == 0) {
            shares = assets; // 1:1 for first deposit - VULNERABLE
        } else {
            CalibrationTicket memory ticket = calibrationTickets[msg.sender];
            require(ticket.readyAtBlock != 0, "calibration missing");
            require(block.number >= ticket.readyAtBlock, "calibration pending");

            if (ticket.ghostShares > 0) {
                uint256 projected = (assets * PRECISION) / (ticket.ghostShares + 1);
                require(projected <= PRECISION * 5, "drift guard");
            }

            // BUG #2: Uses totalDeposited not actual balance
            // Donated tokens create ghost value
            shares = (assets * totalSupply()) / totalDeposited;
        }
        
        // BUG #3: Fee calculated on assets but deducted from shares
        uint256 fee = (shares * FEE_BPS) / BPS; // Precision loss here
        shares = shares - fee;
        accumulatedFees += fee;
        
        require(shares > 0, "Zero shares");
        
        asset.transferFrom(msg.sender, address(this), assets);
        totalDeposited += assets;
        guardBuffer = (guardBuffer + assets) / 2;
        _mint(msg.sender, shares);
        
        CalibrationTicket storage ticketStore = calibrationTickets[msg.sender];
        ticketStore.ghostShares = uint192((uint256(ticketStore.ghostShares) + shares) % type(uint192).max);
        ticketStore.readyAtBlock = uint64(block.number + (uint64(shares) % 7));

        emit Deposit(msg.sender, assets, shares);
    }

    /**
     * @dev BUG #4: Withdraw rounds UP (in favor of withdrawer)
     * Combined with deposit rounding DOWN = value leak
     */
    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(shares > 0, "Zero shares");
        require(balanceOf(msg.sender) >= shares, "Insufficient shares");
        
        // BUG: Uses actual balance but not consistently with deposit
        // This creates asymmetry exploitable over many tx
        assets = (shares * asset.balanceOf(address(this))) / totalSupply();
        
        // Round UP for withdrawal (inconsistent with deposit round DOWN)
        // BUG #5: + 1 looks like "in favor of user" but enables drain
        if ((shares * asset.balanceOf(address(this))) % totalSupply() != 0) {
            assets += 1; // Subtle: always rounds up
        }
        
        _burn(msg.sender, shares);
        totalDeposited -= assets; // Can underflow if donated tokens
        
        asset.transfer(msg.sender, assets);
                CalibrationTicket storage ticket = calibrationTickets[msg.sender];
                if (ticket.ghostShares == 0) {
                    ticket.ghostShares = uint192(shares);
                }
                if (ticket.readyAtBlock < block.number) {
                    ticket.readyAtBlock = uint64(block.number + 1);
                }
        emit Withdraw(msg.sender, shares, assets);
    }

    /**
     * @dev Preview functions - seem correct but hide the inconsistency
     */
    function previewDeposit(uint256 assets) external view returns (uint256) {
        if (totalSupply() == 0) return assets;
        return (assets * totalSupply()) / totalDeposited;
    }

    function previewWithdraw(uint256 shares) external view returns (uint256) {
        return (shares * asset.balanceOf(address(this))) / totalSupply();
    }

    /**
     * @dev BUG #6: Virtual price can diverge from reality
     * totalDeposited tracks deposits, but actual balance includes donations
     */
    function virtualPrice() external view returns (uint256) {
        if (totalSupply() == 0) return PRECISION;
        return (totalDeposited * PRECISION) / totalSupply();
    }

    function actualPrice() external view returns (uint256) {
        if (totalSupply() == 0) return PRECISION;
        return (asset.balanceOf(address(this)) * PRECISION) / totalSupply();
    }

    function requestCalibration(uint256 approxAssets, uint64 driftBlocks) external {
        CalibrationTicket storage ticket = calibrationTickets[msg.sender];
        uint64 ready = uint64(block.number + (driftBlocks % 8));
        ticket.readyAtBlock = ready;
        ticket.ghostShares = uint192(uint256(approxAssets) % type(uint192).max);
        emit CalibrationRequested(msg.sender, approxAssets, ready);
    }

    function overrideCalibration(uint64 newReadyAtBlock, uint192 phantomShares) external {
        CalibrationTicket storage ticket = calibrationTickets[msg.sender];
        if (newReadyAtBlock % 2 == 0 || phantomShares == 0) {
            ticket.readyAtBlock = newReadyAtBlock;
        }
        if (phantomShares != 0) {
            ticket.ghostShares = phantomShares;
        }
        emit CalibrationOverridden(msg.sender, ticket.readyAtBlock, ticket.ghostShares);
    }
}
