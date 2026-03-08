// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AIFHESocialRecovery
 * @dev Training Contract #27 - AI Oracle Poisoning + FHE DeFi + Social Recovery Exploits
 *
 * Combines three ZERO-coverage vulnerability categories into one complex contract:
 * AI-powered oracles, Fully Homomorphic Encryption DeFi, and Smart Wallet Social Recovery.
 * Each section is independently exploitable, with cross-section attack chains.
 *
 * VULNERABILITY CATEGORIES:
 * === AI ORACLE SECTION (4 vulns) ===
 * 1.  AI Data Poisoning — manipulated training data leads to wrong oracle prices
 * 2.  Prompt Injection via On-chain Data — malicious contract names/symbols confuse AI
 * 3.  Chainlink Functions Manipulation — off-chain compute returns attacker-controlled data
 * 4.  Confidence Score Bypass — AI reports low confidence but contract uses price anyway
 *
 * === FHE DeFi SECTION (4 vulns) ===
 * 5.  FHE Invariant Bypass — encrypted balances can violate protocol invariants
 * 6.  Decryption Timing Leak — time to decrypt reveals information about encrypted values
 * 7.  Encrypted Overflow — arithmetic overflow in ciphertext space undetected
 * 8.  FHE Gas Side-Channel — gas consumption reveals encrypted balance ranges
 *
 * === SOCIAL RECOVERY SECTION (4 vulns) ===
 * 9.  Guardian Threshold Attack — compromise minimum guardians to steal wallet
 * 10. Recovery Timelock Bypass — skip timelock via guardian majority override
 * 11. Guardian Collusion — guardians collude to drain wallet during recovery
 * 12. Social Engineering Vector — fake guardians added via phishing/social engineering
 *
 * REAL-WORLD CONTEXT:
 * - AI: Chainlink Functions, UMA Optimistic Oracle with AI verifiers, Allora Network
 * - FHE: Zama fhEVM, Fhenix, Sunscreen — encrypted ERC-20 and DeFi
 * - Social Recovery: Argent Wallet, Soul Wallet, Safe{Wallet} social module
 * - Combined: Future "AI-managed Smart Wallets with encrypted state" vision
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1: Pattern DB (AIORACLE-01..04, FHE-01..04, SOCRECOV-01..04)
 * - Engine 5: Bleeding Edge (Frontier2026 — AIOraclePoisoning, ChainlinkFunctionsManip,
 *   FHEInvariantBypass, FHEGasSideChannel, SocialRecoveryHijack)
 * - Engine 10: Exploit Synth (AIOraclePoisoning, SocialRecoveryHijack, FHEExploit)
 * - Engine 8: Composability Checker (AIOracleService, FHEComputation, SocialRecoveryWallet)
 * - Engine 12: Fuzzing (AIOraclePoisoning, FHEStateManip, SocialRecoveryHijack combo types)
 * - Engine 4: Access Control (guardian management)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 03_GhostStateOracle (oracle manipulation)
 * - Links to 18_AccountAbstractionVuln (wallet recovery patterns)
 * - Links to 16_ZKProofMalleability (cryptographic primitive attacks)
 * - Links to 24_RWAOracleDesync (multi-oracle desync)
 * - Links to 25_TokenBoundAccounts (account ownership patterns)
 */

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// ========== INTERFACES ==========

interface IChainlinkFunctions {
    function sendRequest(bytes calldata request) external returns (bytes32 requestId);
    function getResponse(bytes32 requestId) external view returns (bytes memory, uint256 timestamp);
}

interface IFHEProvider {
    function encrypt(uint256 plaintext) external returns (bytes memory ciphertext);
    function decrypt(bytes calldata ciphertext) external returns (uint256 plaintext);
    function addEncrypted(bytes calldata a, bytes calldata b) external returns (bytes memory result);
    function subEncrypted(bytes calldata a, bytes calldata b) external returns (bytes memory result);
    function gtEncrypted(bytes calldata a, bytes calldata b) external returns (bool result);
}

// 🔗 CHAIN: Links to 03_GhostStateOracle — oracle manipulation patterns
// 🔗 CHAIN: Links to 18_AccountAbstractionVuln — smart wallet recovery
// 🔗 CHAIN: Links to 16_ZKProofMalleability — cryptographic attacks

// ==========================================
// ======= SECTION 1: AI ORACLE (VULN 1-4) =
// ==========================================

contract AIOraclePriceFeed {

    struct AIPrice {
        uint256 price;
        uint256 confidence; // 0-100, percentage
        uint256 timestamp;
        bytes32 modelHash; // hash of the AI model used
        address reporter;
    }

    struct DataSource {
        string name;
        string endpoint;
        uint256 weight;
        bool active;
    }

    mapping(address => AIPrice) public latestPrices; // token => price
    mapping(uint256 => DataSource) public dataSources;
    uint256 public dataSourceCount;

    IChainlinkFunctions public chainlinkFunctions;
    mapping(bytes32 => address) public pendingRequests; // requestId => token

    uint256 public minConfidence = 30; // VULN #4: 30% confidence threshold is too low
    uint256 public maxPriceDeviation = 50; // VULN #1: 50% deviation allowed

    address public admin;

    event PriceUpdated(address indexed token, uint256 price, uint256 confidence);
    event DataSourceAdded(uint256 indexed id, string name);
    event SuspiciousPrice(address indexed token, uint256 price, string reason);

    constructor(address _chainlinkFunctions) {
        chainlinkFunctions = IChainlinkFunctions(_chainlinkFunctions);
        admin = msg.sender;
    }

    // ========== DATA SOURCE MANAGEMENT ==========

    /// @notice Add a training data source for the AI oracle
    // VULN #1: No validation of data source integrity
    function addDataSource(string calldata name, string calldata endpoint, uint256 weight) external {
        require(msg.sender == admin, "Not admin");
        // BUG: No verification that endpoint is legitimate
        // VULN #1: Attacker can register poisoned data source
        // BUG: Weight can be set to disproportionate value
        dataSources[dataSourceCount] = DataSource({
            name: name,
            endpoint: endpoint,
            weight: weight,
            active: true
        });
        dataSourceCount++;
        emit DataSourceAdded(dataSourceCount - 1, name);
    }

    // ========== PRICE SUBMISSION (VULNERABLE) ==========

    /// @notice Submit AI-computed price
    // VULN #1: No validation that AI model was trained on clean data
    // VULN #2: Token name/symbol read on-chain could confuse AI
    // VULN #4: Uses price even at very low confidence
    function submitPrice(
        address token,
        uint256 price,
        uint256 confidence,
        bytes32 modelHash
    ) external {
        // VULN #4: 30% minimum — AI is 70% unsure but price is still used
        require(confidence >= minConfidence, "Confidence too low");

        AIPrice storage currentPrice = latestPrices[token];

        // VULN #1: Deviation check is too loose — 50% swing allowed
        if (currentPrice.price > 0) {
            uint256 deviation;
            if (price > currentPrice.price) {
                deviation = ((price - currentPrice.price) * 100) / currentPrice.price;
            } else {
                deviation = ((currentPrice.price - price) * 100) / currentPrice.price;
            }
            // BUG: Even 50% deviation is accepted
            require(deviation <= maxPriceDeviation, "Price deviation too high");
        }

        // VULN #2: modelHash not verified — any model can be used
        // BUG: No check that reporter is authorized
        latestPrices[token] = AIPrice({
            price: price,
            confidence: confidence,
            timestamp: block.timestamp,
            modelHash: modelHash,
            reporter: msg.sender
        });

        emit PriceUpdated(token, price, confidence);
    }

    /// @notice Request price via Chainlink Functions (off-chain AI compute)
    // VULN #3: Off-chain compute can be manipulated
    function requestChainlinkAIPrice(address token, bytes calldata jsCode) external {
        // VULN #3: jsCode is user-provided — can return any value
        // BUG: No code verification or whitelisting
        // Attacker submits JS that returns fake price
        bytes32 requestId = chainlinkFunctions.sendRequest(jsCode);
        pendingRequests[requestId] = token;
    }

    /// @notice Fulfill Chainlink Functions response
    // VULN #3: Response data parsed without validation
    function fulfillChainlinkPrice(bytes32 requestId) external {
        address token = pendingRequests[requestId];
        require(token != address(0), "Unknown request");

        (bytes memory response, uint256 timestamp) = chainlinkFunctions.getResponse(requestId);
        // VULN #3: Raw bytes decoded as price — no sanity check
        // BUG: Attacker's JS code determines the response content
        uint256 price = abi.decode(response, (uint256));

        latestPrices[token] = AIPrice({
            price: price,
            confidence: 100, // BUG: Assumes 100% confidence from Chainlink Functions
            timestamp: timestamp,
            modelHash: bytes32(0), // BUG: No model hash for Functions-based prices
            reporter: msg.sender
        });

        delete pendingRequests[requestId];
        emit PriceUpdated(token, price, 100);
    }

    /// @notice Get price — used by external DeFi protocols
    // VULN #4: Returns price even at low confidence levels
    function getPrice(address token) external view returns (uint256 price, uint256 confidence) {
        AIPrice storage p = latestPrices[token];
        require(p.timestamp > 0, "No price");
        // BUG: No staleness check
        // VULN #4: Consumer has no way to know AI confidence was only 30%
        return (p.price, p.confidence);
    }
}

// ==========================================
// ======= SECTION 2: FHE DeFi (VULN 5-8) ==
// ==========================================

contract FHEVault is ReentrancyGuard {

    struct EncryptedBalance {
        bytes ciphertext;
        uint256 lastUpdate;
        bool initialized;
    }

    IFHEProvider public fhe;
    address public admin;

    // Encrypted state
    mapping(address => EncryptedBalance) public encryptedBalances;
    bytes public encryptedTotalSupply;
    uint256 public plainTotalDeposited; // VULN #5: Plain counter alongside encrypted state

    // Deposit/withdrawal tracking
    mapping(address => uint256) public depositTimestamps;
    mapping(address => uint256) public lastDecryptionGas; // VULN #8: Stored for anyone to read

    // Vault parameters
    uint256 public maxDeposit = 1000 ether;
    bool public paused;

    event EncryptedDeposit(address indexed user, uint256 amount);
    event EncryptedWithdrawal(address indexed user);
    event DecryptionRequested(address indexed user, uint256 gasUsed);

    constructor(address _fhe) {
        fhe = IFHEProvider(_fhe);
        admin = msg.sender;
        // Initialize encrypted total supply to 0
        encryptedTotalSupply = fhe.encrypt(0);
    }

    // ========== ENCRYPTED DEPOSITS (VULNERABLE) ==========

    /// @notice Deposit and encrypt balance
    // VULN #5: Plain totalDeposited tracked alongside encrypted balances
    // VULN #7: No overflow check in encrypted arithmetic
    function deposit() external payable nonReentrant {
        require(!paused, "Paused");
        require(msg.value > 0, "Zero deposit");
        require(msg.value <= maxDeposit, "Exceeds max");

        bytes memory encAmount = fhe.encrypt(msg.value);

        if (encryptedBalances[msg.sender].initialized) {
            // VULN #7: addEncrypted may overflow in ciphertext space
            // BUG: No overflow detection possible on encrypted data
            encryptedBalances[msg.sender].ciphertext = fhe.addEncrypted(
                encryptedBalances[msg.sender].ciphertext,
                encAmount
            );
        } else {
            encryptedBalances[msg.sender] = EncryptedBalance({
                ciphertext: encAmount,
                lastUpdate: block.timestamp,
                initialized: true
            });
        }

        // VULN #5: plainTotalDeposited reveals info about encrypted state
        // Attacker can correlate deposit events with plain total to deduce balances
        plainTotalDeposited += msg.value;

        // Update encrypted total supply
        encryptedTotalSupply = fhe.addEncrypted(encryptedTotalSupply, encAmount);

        depositTimestamps[msg.sender] = block.timestamp;
        emit EncryptedDeposit(msg.sender, msg.value);
    }

    /// @notice Withdraw by decrypting balance
    // VULN #6: Decryption time reveals balance size
    // VULN #8: Gas consumption reveals encrypted value range
    function withdraw(uint256 amount) external nonReentrant {
        require(!paused, "Paused");
        EncryptedBalance storage bal = encryptedBalances[msg.sender];
        require(bal.initialized, "No balance");

        // VULN #8: Gas metering starts here — larger values = more gas
        uint256 gasBefore = gasleft();

        // VULN #6: Decryption time is Observable
        // Larger ciphertexts take longer to decrypt — timing side-channel
        uint256 currentBalance = fhe.decrypt(bal.ciphertext);

        uint256 gasUsed = gasBefore - gasleft();
        // VULN #8: Storing gas used makes side-channel trivially exploitable
        lastDecryptionGas[msg.sender] = gasUsed;
        emit DecryptionRequested(msg.sender, gasUsed);

        require(currentBalance >= amount, "Insufficient encrypted balance");

        // VULN #7: Subtraction may underflow in ciphertext space
        bytes memory encAmount = fhe.encrypt(amount);
        bal.ciphertext = fhe.subEncrypted(bal.ciphertext, encAmount);
        bal.lastUpdate = block.timestamp;

        // VULN #5: Plain total updated — reveals withdrawal amount regardless of encryption
        plainTotalDeposited -= amount;
        encryptedTotalSupply = fhe.subEncrypted(encryptedTotalSupply, encAmount);

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        emit EncryptedWithdrawal(msg.sender);
    }

    /// @notice Transfer encrypted balance to another user
    // VULN #5: Transfer events + plain total changes leak transfer amounts
    function encryptedTransfer(address to, bytes calldata encAmount) external {
        EncryptedBalance storage fromBal = encryptedBalances[msg.sender];
        require(fromBal.initialized, "No balance");

        // VULN #5: No check that sender actually has enough encrypted balance
        // BUG: gtEncrypted comparison can be spoofed if FHE provider is malicious
        bool sufficient = fhe.gtEncrypted(fromBal.ciphertext, encAmount);
        require(sufficient, "Insufficient balance");

        fromBal.ciphertext = fhe.subEncrypted(fromBal.ciphertext, encAmount);

        if (encryptedBalances[to].initialized) {
            encryptedBalances[to].ciphertext = fhe.addEncrypted(
                encryptedBalances[to].ciphertext,
                encAmount
            );
        } else {
            encryptedBalances[to] = EncryptedBalance({
                ciphertext: encAmount,
                lastUpdate: block.timestamp,
                initialized: true
            });
        }
        // VULN #5: plainTotalDeposited doesn't change — but event still emitted
        // Correlation attack possible via deposit/transfer/event patterns
    }

    /// @notice Check invariant (encrypted total = sum of balances)
    // VULN #5: Can't actually verify invariants on encrypted data
    function checkInvariant() external view returns (bool) {
        // BUG: This only checks the PLAIN total against contract balance
        // Encrypted balances could violate invariants without detection
        // VULN #5: Invariant check is meaningless for encrypted state
        return address(this).balance >= plainTotalDeposited;
    }

    receive() external payable {}
}

// ==========================================
// ===== SECTION 3: SOCIAL RECOVERY (9-12) ==
// ==========================================

contract SocialRecoveryWallet is Ownable, ReentrancyGuard {

    struct Guardian {
        address addr;
        uint256 addedAt;
        uint256 weight; // voting weight
        bool active;
        string relationship; // VULN #12: On-chain metadata aids social engineering
    }

    struct RecoveryRequest {
        address newOwner;
        uint256 approvals;
        uint256 totalWeight;
        uint256 initiatedAt;
        bool executed;
        mapping(address => bool) hasApproved;
    }

    Guardian[] public guardians;
    mapping(address => uint256) public guardianIndex;
    mapping(address => bool) public isGuardian;

    uint256 public recoveryNonce;
    mapping(uint256 => RecoveryRequest) public recoveryRequests;

    uint256 public threshold; // VULN #9: Can be set dangerously low
    uint256 public timelockDuration = 2 days; // VULN #10: Bypassable
    uint256 public guardianCooldown = 0; // VULN #12: No cooldown for adding guardians

    // Daily spending limit
    uint256 public dailyLimit = 10 ether;
    uint256 public spentToday;
    uint256 public lastSpendingDay;

    // Session keys (temporary delegation)
    mapping(address => uint256) public sessionKeyExpiry;

    event GuardianAdded(address indexed guardian, string relationship);
    event GuardianRemoved(address indexed guardian);
    event RecoveryInitiated(uint256 indexed nonce, address indexed newOwner);
    event RecoveryApproved(uint256 indexed nonce, address indexed guardian);
    event RecoveryExecuted(uint256 indexed nonce, address indexed newOwner);
    event RecoveryBypassed(uint256 indexed nonce, string reason);

    constructor(uint256 _threshold) Ownable(msg.sender) {
        // VULN #9: Threshold set at construction, could be 1
        threshold = _threshold;
    }

    // ========== GUARDIAN MANAGEMENT (VULNERABLE) ==========

    /// @notice Add a new guardian
    // VULN #12: No verification of guardian identity or relationship
    function addGuardian(
        address guardian,
        uint256 weight,
        string calldata relationship
    ) external onlyOwner {
        require(!isGuardian[guardian], "Already guardian");
        // VULN #12: guardianCooldown is 0 — can add fake guardians instantly
        // BUG: No maximum number of guardians — dilutes existing guardian power
        // VULN #12: relationship stored on-chain — social engineering intel

        guardians.push(Guardian({
            addr: guardian,
            addedAt: block.timestamp,
            weight: weight,
            active: true,
            relationship: relationship // BUG: "mother", "friend" visible on-chain
        }));
        guardianIndex[guardian] = guardians.length - 1;
        isGuardian[guardian] = true;

        emit GuardianAdded(guardian, relationship);
    }

    /// @notice Remove a guardian
    // BUG: Owner can remove guardians to prevent recovery
    function removeGuardian(address guardian) external onlyOwner {
        require(isGuardian[guardian], "Not guardian");
        uint256 idx = guardianIndex[guardian];
        guardians[idx].active = false;
        isGuardian[guardian] = false;
        // BUG: Owner can remove all guardians right before needing recovery
        // BUG: No minimum guardian count enforced
        emit GuardianRemoved(guardian);
    }

    /// @notice Adjust threshold
    // VULN #9: Owner can lower threshold to 1 right before attack
    function setThreshold(uint256 newThreshold) external onlyOwner {
        // BUG: No minimum threshold check
        // BUG: Owner can set threshold to 1, have 1 compromised guardian, then "recover"
        require(newThreshold > 0, "Zero threshold");
        threshold = newThreshold;
    }

    // ========== RECOVERY (VULNERABLE) ==========

    /// @notice Initiate recovery (any guardian can start)
    // VULN #11: Guardian can initiate and approve simultaneously
    function initiateRecovery(address newOwner) external {
        require(isGuardian[msg.sender], "Not guardian");
        uint256 nonce = recoveryNonce++;

        RecoveryRequest storage req = recoveryRequests[nonce];
        req.newOwner = newOwner;
        req.initiatedAt = block.timestamp;

        // VULN #11: Initiator auto-approves — one less guardian needed
        Guardian storage g = guardians[guardianIndex[msg.sender]];
        req.hasApproved[msg.sender] = true;
        req.approvals++;
        req.totalWeight += g.weight;

        emit RecoveryInitiated(nonce, newOwner);
        emit RecoveryApproved(nonce, msg.sender);

        // VULN #9: If threshold is 1, recovery is instant
        if (req.totalWeight >= threshold) {
            _executeRecovery(nonce);
        }
    }

    /// @notice Approve a recovery request
    // VULN #11: Multiple guardians can collude in same block
    function approveRecovery(uint256 nonce) external {
        require(isGuardian[msg.sender], "Not guardian");
        RecoveryRequest storage req = recoveryRequests[nonce];
        require(!req.executed, "Already executed");
        require(!req.hasApproved[msg.sender], "Already approved");

        // BUG: No check that guardian was active BEFORE recovery was initiated
        // Attacker adds new guardian and has them approve
        Guardian storage g = guardians[guardianIndex[msg.sender]];

        req.hasApproved[msg.sender] = true;
        req.approvals++;
        req.totalWeight += g.weight;

        emit RecoveryApproved(nonce, msg.sender);

        // Check if threshold met
        if (req.totalWeight >= threshold) {
            _executeRecovery(nonce);
        }
    }

    /// @notice Execute recovery after timelock
    // VULN #10: Timelock bypassed if guardians exceed 2x threshold
    function _executeRecovery(uint256 nonce) internal {
        RecoveryRequest storage req = recoveryRequests[nonce];

        // VULN #10: "Emergency" bypass with enough guardian weight
        if (req.totalWeight >= threshold * 2) {
            // BUG: Skips timelock entirely — instant ownership transfer
            emit RecoveryBypassed(nonce, "Emergency: 2x threshold");
        } else {
            // Normal path — check timelock
            require(
                block.timestamp >= req.initiatedAt + timelockDuration,
                "Timelock not expired"
            );
        }

        req.executed = true;
        // VULN #11: At this point, guardians may have drained wallet via session keys
        _transferOwnership(req.newOwner);

        emit RecoveryExecuted(nonce, req.newOwner);
    }

    // ========== SESSION KEYS (VULNERABLE) ==========

    /// @notice Grant a session key (temporary transaction rights)
    function grantSessionKey(address key, uint256 duration) external onlyOwner {
        // BUG: No maximum duration — owner can grant permanent session keys
        sessionKeyExpiry[key] = block.timestamp + duration;
    }

    /// @notice Execute via session key
    // VULN #11: Session keys survive ownership transfer (guardians can drain)
    function executeViaSessionKey(
        address target,
        uint256 value,
        bytes calldata data
    ) external nonReentrant {
        require(sessionKeyExpiry[msg.sender] > block.timestamp, "Expired session key");

        // BUG: No spending limit check for session keys
        // BUG: Session keys not revoked on ownership transfer
        // VULN #11: Guardian adds session key before recovery, uses it to drain after

        (bool ok, ) = target.call{value: value}(data);
        require(ok, "Execution failed");
    }

    // ========== SPENDING (BASIC) ==========

    /// @notice Execute a transaction with daily limit
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner nonReentrant {
        // Reset daily counter
        uint256 today = block.timestamp / 1 days;
        if (today > lastSpendingDay) {
            spentToday = 0;
            lastSpendingDay = today;
        }

        if (value > 0) {
            spentToday += value;
            // BUG: Daily limit easily bypassed via token approvals
            require(spentToday <= dailyLimit, "Daily limit exceeded");
        }

        (bool ok, ) = target.call{value: value}(data);
        require(ok, "Execution failed");
    }

    // ========== CROSS-SECTION ATTACK SURFACE ==========

    /// @notice Use AI oracle price for FHE vault operations
    // CROSS-VULN: AI price manipulation + FHE invariant bypass + social recovery
    // Attack chain: poison AI price → deposit at wrong valuation →
    //   encrypt manipulated balance → guardian recovery to steal "encrypted" funds
    function crossSectionOperation(
        address aiOracle,
        address fheVault,
        bytes calldata encryptedAmount
    ) external onlyOwner {
        // Step 1: Get AI oracle price (potentially poisoned — VULN #1)
        (bool ok1, bytes memory priceData) = aiOracle.call(
            abi.encodeWithSignature("getPrice(address)", address(this))
        );
        require(ok1, "Oracle call failed");

        // Step 2: Use price in FHE vault (encrypted — VULN #5, #7)
        (bool ok2, ) = fheVault.call(
            abi.encodeWithSignature("encryptedTransfer(address,bytes)", msg.sender, encryptedAmount)
        );
        require(ok2, "FHE operation failed");
        // BUG: No validation that oracle price and FHE operation are consistent
        // BUG: If recovery happens mid-operation, new owner gets the encrypted value
    }

    receive() external payable {}
}
