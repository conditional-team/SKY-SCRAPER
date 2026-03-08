// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title RWAOracleDesync
 * @dev Training Contract #24 - Real-World Asset Oracle Desync & Compliance Exploits
 *
 * Simulates a tokenized RWA protocol with NAV oracle, compliance checks,
 * redemption windows, and multi-oracle pricing — all vulnerable to 2026-era attacks.
 *
 * VULNERABILITY CATEGORIES:
 * 1.  NAV Oracle Staleness — off-chain NAV updated daily but on-chain price used continuously
 * 2.  Compliance Oracle Bypass — KYC/AML status cached, can trade between revocation + update
 * 3.  Redemption Race Condition — redeem at stale NAV before oracle update settles
 * 4.  Treasury Proof Staleness — proof-of-reserves attestation accepted days after generation
 * 5.  Collateral Proof Fraud — Chainlink PoR feed spoofable via report manipulation
 * 6.  Multi-Oracle Desync — Chainlink vs API3 vs custom oracle show different prices
 * 7.  NAV Sandwich — front-run NAV update with large mint, back-run with redeem at new NAV
 * 8.  Dividend Flash Loan — flash-loan tokens to claim accrued dividends then return
 * 9.  Compliance Frontrun — see pending KYC revocation in mempool, dump before blacklist
 * 10. Off-chain Settlement Gap — on-chain transfer settles instantly but real asset T+2
 * 11. Time-zone Arbitrage — NAV priced at NYC close but redeemable in any timezone
 * 12. Regulatory Jurisdiction Hop — transfer tokens cross-chain to avoid compliance oracle
 *
 * REAL-WORLD CONTEXT:
 * - Ondo Finance, Centrifuge, Maple Finance RWA protocols
 * - MakerDAO RWA vaults (MIP65, MIP81) — off-chain collateral trust issues
 * - BlackRock BUIDL, Franklin Templeton on-chain funds
 * - T+1 settlement mismatch (SEC 2024 rule change)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1: Pattern DB (RWA-01..06 patterns)
 * - Engine 5: Bleeding Edge (Frontier2026 — RWAOracleDesync)
 * - Engine 10: Exploit Synth (RWADesync attack synthesis)
 * - Engine 7: Temporal Analyzer (staleness windows, settlement gaps)
 * - Engine 8: Composability Checker (RWAOracle external class)
 * - Engine 12: Fuzzing (RWAOracleDesync combo type)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 03_GhostStateOracle (oracle manipulation patterns)
 * - Links to 14_SequencerDownOracle (oracle downtime exploitation)
 * - Links to 19_BridgeOracleManipulation (cross-chain oracle attacks)
 * - Links to 22_PectraExploits (cross-chain compliance bypass via EIP-7702)
 */

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// ========== INTERFACES ==========

interface INavOracle {
    function getNav() external view returns (uint256 nav, uint256 timestamp);
    function updateNav(uint256 newNav, bytes calldata proof) external;
}

interface IComplianceOracle {
    function isCompliant(address user) external view returns (bool);
    function getComplianceTimestamp(address user) external view returns (uint256);
}

interface IProofOfReserves {
    function getReserves() external view returns (uint256 reserves, uint256 attestationTime);
    function verifyProof(bytes calldata proof) external view returns (bool);
}

interface ISecondaryOracle {
    function getPrice() external view returns (uint256);
}

// 🔗 CHAIN: Links to 03_GhostStateOracle — oracle interface pattern
// 🔗 CHAIN: Links to 14_SequencerDownOracle — oracle downtime checks

// ========== NAV ORACLE (VULNERABLE) ==========

contract VulnerableNavOracle is INavOracle {
    uint256 public currentNav;
    uint256 public lastUpdateTime;
    address public updater;

    // VULN #1: No staleness check — NAV can be hours/days old
    // VULN #5: No proof verification — updater can submit arbitrary NAV
    constructor(uint256 initialNav) {
        currentNav = initialNav;
        lastUpdateTime = block.timestamp;
        updater = msg.sender;
    }

    function getNav() external view override returns (uint256, uint256) {
        // BUG: Returns stale NAV without any freshness validation
        return (currentNav, lastUpdateTime);
    }

    function updateNav(uint256 newNav, bytes calldata /* proof */) external override {
        // VULN #5: Proof parameter completely ignored
        // VULN #1: No maximum staleness enforcement
        require(msg.sender == updater, "Not updater");

        // BUG: No deviation check — NAV can jump 100x in one update
        currentNav = newNav;
        lastUpdateTime = block.timestamp;
    }
}

// ========== COMPLIANCE ORACLE (VULNERABLE) ==========

contract VulnerableComplianceOracle is IComplianceOracle {
    mapping(address => bool) public compliant;
    mapping(address => uint256) public complianceTimestamp;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    // VULN #2: Compliance status cached — gap between revocation and on-chain update
    function setCompliance(address user, bool status) external {
        require(msg.sender == admin, "Not admin");
        compliant[user] = status;
        complianceTimestamp[user] = block.timestamp;
    }

    function isCompliant(address user) external view override returns (bool) {
        // BUG: No expiry check on compliance status
        // Status could be months old and still return true
        return compliant[user];
    }

    function getComplianceTimestamp(address user) external view override returns (uint256) {
        return complianceTimestamp[user];
    }
}

// ========== MAIN RWA TOKEN (VULNERABLE) ==========

contract RWAOracleDesync is ERC20, Ownable, ReentrancyGuard {

    // ========== STATE ==========
    INavOracle public navOracle;
    IComplianceOracle public complianceOracle;
    IProofOfReserves public porOracle;
    ISecondaryOracle public secondaryOracle;

    uint256 public constant PRECISION = 1e18;
    uint256 public constant MIN_REDEMPTION = 1000e18;

    // Treasury tracking
    uint256 public totalDeposited;
    uint256 public lastPorCheck;
    uint256 public porStalenessThreshold; // VULN #4: configurable, can be set very high

    // Dividend system
    uint256 public dividendPerToken;
    mapping(address => uint256) public lastDividendClaimed;
    mapping(address => uint256) public dividendDebt;

    // Redemption queue
    struct RedemptionRequest {
        address redeemer;
        uint256 shares;
        uint256 navAtRequest;
        uint256 requestTime;
        bool fulfilled;
    }
    RedemptionRequest[] public redemptionQueue;
    uint256 public redemptionDelay; // VULN #10: doesn't match T+2 settlement

    // Compliance
    mapping(address => bool) public whitelisted;
    uint256 public complianceMaxAge; // VULN #2: max age of compliance check

    // Cross-chain
    mapping(uint256 => bool) public approvedChains;
    mapping(uint256 => address) public chainBridges;

    // ========== EVENTS ==========
    event Minted(address indexed user, uint256 amount, uint256 nav);
    event RedemptionRequested(uint256 indexed id, address indexed user, uint256 shares);
    event RedemptionFulfilled(uint256 indexed id, uint256 payout);
    event DividendClaimed(address indexed user, uint256 amount);
    event NavUpdated(uint256 oldNav, uint256 newNav);
    event ComplianceRevoked(address indexed user);

    constructor(
        address _navOracle,
        address _complianceOracle,
        address _porOracle,
        address _secondaryOracle
    ) ERC20("RWA Token", "RWAT") Ownable(msg.sender) {
        navOracle = INavOracle(_navOracle);
        complianceOracle = IComplianceOracle(_complianceOracle);
        porOracle = IProofOfReserves(_porOracle);
        secondaryOracle = ISecondaryOracle(_secondaryOracle);

        porStalenessThreshold = 7 days; // VULN #4: 7 days is too long for PoR
        redemptionDelay = 1 hours; // VULN #10: 1 hour vs T+2 real settlement
        complianceMaxAge = 30 days; // VULN #2: 30-day compliance window is exploitable
    }

    // ========== MODIFIERS ==========

    // VULN #2 + #9: Compliance check uses cached status, frontrunnable
    modifier onlyCompliant(address user) {
        require(
            complianceOracle.isCompliant(user),
            "Not compliant"
        );
        // BUG: doesn't check complianceMaxAge against complianceTimestamp
        // BUG: compliance revocation visible in mempool before this check
        _;
    }

    // ========== MINTING (VULNERABLE) ==========

    /// @notice Mint RWA tokens by depositing stablecoins
    // VULN #1 + #7: Uses potentially stale NAV, sandwichable
    function mint(uint256 depositAmount) external onlyCompliant(msg.sender) nonReentrant {
        require(depositAmount > 0, "Zero deposit");

        // VULN #1: NAV could be hours old
        (uint256 nav, uint256 navTimestamp) = navOracle.getNav();
        // BUG: No staleness check on navTimestamp
        // BUG: No check that nav > 0

        // VULN #7: Attacker sees NAV update in mempool, frontruns with mint
        uint256 sharesToMint = (depositAmount * PRECISION) / nav;

        // BUG: No slippage protection — attacker gets shares at stale price
        _mint(msg.sender, sharesToMint);
        totalDeposited += depositAmount;

        // VULN #8: Dividend snapshot not reset — inherits accrued dividends
        // BUG: dividendDebt not set for new minter
        // lastDividendClaimed[msg.sender] should be set to dividendPerToken

        emit Minted(msg.sender, sharesToMint, nav);
    }

    // ========== REDEMPTION (VULNERABLE) ==========

    /// @notice Request redemption at current NAV
    // VULN #3: Redeems at stale NAV before oracle update
    // VULN #10: On-chain instant but real asset T+2
    function requestRedemption(uint256 shares) external onlyCompliant(msg.sender) {
        require(shares >= MIN_REDEMPTION, "Below minimum");
        require(balanceOf(msg.sender) >= shares, "Insufficient balance");

        (uint256 nav, ) = navOracle.getNav();
        // VULN #3: NAV locked at request time — if real NAV drops, redeemer profits

        // BUG: Tokens not locked/burned until fulfillment
        // Redeemer can transfer tokens away and still have redemption valid

        redemptionQueue.push(RedemptionRequest({
            redeemer: msg.sender,
            shares: shares,
            navAtRequest: nav, // VULN #3: Stale NAV frozen here
            requestTime: block.timestamp,
            fulfilled: false
        }));

        emit RedemptionRequested(redemptionQueue.length - 1, msg.sender, shares);
    }

    /// @notice Fulfill redemption after delay
    // VULN #10: Delay doesn't match real settlement time
    function fulfillRedemption(uint256 requestId) external onlyCompliant(msg.sender) {
        RedemptionRequest storage req = redemptionQueue[requestId];
        require(!req.fulfilled, "Already fulfilled");
        require(msg.sender == req.redeemer, "Not redeemer");
        require(
            block.timestamp >= req.requestTime + redemptionDelay,
            "Too early"
        );
        // VULN #10: redemptionDelay is 1 hour but real asset settles T+2

        // BUG: No check that redeemer still has the shares
        // They could have transferred shares after requesting redemption
        uint256 payout = (req.shares * req.navAtRequest) / PRECISION;

        req.fulfilled = true;
        _burn(msg.sender, req.shares);
        totalDeposited -= payout;

        // BUG: Direct ETH transfer without pull pattern
        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "Transfer failed");

        emit RedemptionFulfilled(requestId, payout);
    }

    // ========== DIVIDEND SYSTEM (VULNERABLE) ==========

    /// @notice Distribute dividends to all holders
    function distributeDividend() external payable onlyOwner {
        require(totalSupply() > 0, "No supply");
        dividendPerToken += (msg.value * PRECISION) / totalSupply();
    }

    /// @notice Claim accrued dividends
    // VULN #8: Flash-loanable — borrow tokens, claim dividends, return
    function claimDividend() external onlyCompliant(msg.sender) nonReentrant {
        uint256 owed = (balanceOf(msg.sender) * (dividendPerToken - lastDividendClaimed[msg.sender])) / PRECISION;
        // BUG: dividendDebt not subtracted — double-claim possible after transfer
        // VULN #8: Balance checked at call time — flash loan inflates balance

        require(owed > 0, "Nothing to claim");
        lastDividendClaimed[msg.sender] = dividendPerToken;

        (bool ok, ) = msg.sender.call{value: owed}("");
        require(ok, "Transfer failed");

        emit DividendClaimed(msg.sender, owed);
    }

    // ========== PROOF OF RESERVES (VULNERABLE) ==========

    /// @notice Verify collateral backing via PoR oracle
    // VULN #4: Attestation accepted even if days old
    // VULN #5: Proof not actually cryptographically verified
    function verifyReserves() external view returns (bool solvent) {
        (uint256 reserves, uint256 attestationTime) = porOracle.getReserves();

        // VULN #4: porStalenessThreshold is 7 days — way too long
        require(
            block.timestamp - attestationTime <= porStalenessThreshold,
            "PoR too stale"
        );

        // BUG: Compares reserves to totalDeposited, not to totalSupply * NAV
        // If NAV changed, this check is meaningless
        solvent = reserves >= totalDeposited;
    }

    // ========== MULTI-ORACLE PRICING (VULNERABLE) ==========

    /// @notice Get "best" price from multiple oracles
    // VULN #6: No median/TWAP — just picks first available
    function getConsensusPrice() public view returns (uint256) {
        (uint256 navPrice, uint256 navTime) = navOracle.getNav();
        uint256 secondaryPrice = secondaryOracle.getPrice();

        // BUG: If NAV oracle is stale, just uses secondary — no deviation check
        if (block.timestamp - navTime > 1 hours) {
            return secondaryPrice; // VULN #6: Single oracle fallback, no validation
        }

        // BUG: Simple average of potentially desynced oracles
        // Should use median or TWAP with deviation bounds
        return (navPrice + secondaryPrice) / 2;
    }

    // ========== CROSS-CHAIN TRANSFER (VULNERABLE) ==========

    /// @notice Bridge tokens to another chain
    // VULN #12: Tokens leave compliance-enforced chain
    function bridgeToChain(uint256 chainId, uint256 amount) external onlyCompliant(msg.sender) {
        require(approvedChains[chainId], "Chain not approved");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

        // VULN #12: Compliance check only on source chain
        // Destination chain may have different/no compliance oracle
        _burn(msg.sender, amount);

        // BUG: No message verification — bridge could mint without real burn
        // BUG: No rate limiting — entire supply can be bridged
        (bool ok, ) = chainBridges[chainId].call(
            abi.encodeWithSignature("mint(address,uint256)", msg.sender, amount)
        );
        require(ok, "Bridge failed");
    }

    // ========== ADMIN (VULNERABLE) ==========

    /// @notice Update oracle addresses — no timelock
    function setNavOracle(address _oracle) external onlyOwner {
        // BUG: No timelock — owner can swap oracle instantly
        navOracle = INavOracle(_oracle);
    }

    function setComplianceOracle(address _oracle) external onlyOwner {
        complianceOracle = IComplianceOracle(_oracle);
    }

    function setPorStaleness(uint256 _threshold) external onlyOwner {
        // VULN #4: No minimum — can set to type(uint256).max
        porStalenessThreshold = _threshold;
    }

    function setRedemptionDelay(uint256 _delay) external onlyOwner {
        // VULN #10: No minimum — can set to 0
        redemptionDelay = _delay;
    }

    function approveChain(uint256 chainId, address bridge) external onlyOwner {
        approvedChains[chainId] = true;
        chainBridges[chainId] = bridge;
    }

    // ========== TIMEZONE ARBITRAGE HELPER ==========

    /// @notice Get NAV update window (hardcoded to 4:00 PM EST)
    // VULN #11: Block.timestamp is UTC, NAV priced at NYC market close
    function isNavUpdateWindow() public view returns (bool) {
        // BUG: Hardcoded timezone offset, doesn't account for DST
        uint256 hourUTC = (block.timestamp / 1 hours) % 24;
        // NYC close = 21:00 UTC (winter) or 20:00 UTC (summer)
        // BUG: Uses fixed 21:00 — wrong half the year
        return hourUTC >= 21 && hourUTC <= 22;
    }

    /// @notice Mint during off-hours at stale NAV
    // VULN #11: Exploitable time-zone gap
    function mintOffHours(uint256 amount) external onlyCompliant(msg.sender) {
        // BUG: No restriction on minting outside NAV update window
        // Attacker mints at yesterday's NAV when today's will be different
        require(!isNavUpdateWindow(), "Wait for update");

        (uint256 nav, ) = navOracle.getNav();
        uint256 shares = (amount * PRECISION) / nav;
        _mint(msg.sender, shares);
        totalDeposited += amount;
    }

    // ========== RECEIVE ==========
    receive() external payable {}
}
