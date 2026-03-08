// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title RestakingSlashingCascade
 * @dev Training Contract #20 - Restaking/EigenLayer Vulnerabilities (2025/2026)
 * 
 * CUTTING EDGE VULNERABILITIES:
 * 1. Slashing cascade - one slash triggers systemic failure
 * 2. AVS trust inflation - fake security claims
 * 3. Withdrawal credential swap - change recipient mid-unstake
 * 4. Operator collusion - multiple AVS same stake
 * 5. Circular restaking (LST → Restaking → LST)
 * 
 * REAL-WORLD EXAMPLES:
 * - EigenLayer slashing risk model concerns
 * - Restaking ponzi patterns
 * - Lido withdrawal credential bugs
 * 
 * CROSS-CONTRACT CHAINS:
 * - Links to 01_PrecisionVault (share inflation in LST)
 * - Links to 07_FlashLoanVictim (flash restake)
 * - Links to 19_BridgeOracleManipulation (cross-chain restaking)
 * - Links to 03_GhostStateOracle (stale restaking rates)
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 5: Economic (slashing economics)
 * - Engine 9: Invariant (stake accounting)
 * - Engine 15: Composability (LST stacking)
 */

// 🔗 CHAIN: Interfaces to existing contracts
interface IPrecisionVault {
    function deposit(uint256 assets) external returns (uint256 shares);
    function withdraw(uint256 shares) external returns (uint256 assets);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanVictim {
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external;
    function getPrice() external view returns (uint256);
}

interface IGhostStateOracle {
    function cachedPrice() external view returns (uint256);
}

interface IBridgeOracleManipulation {
    function chainLiquidity(uint256 chainId) external view returns (uint256);
}

/**
 * @dev Actively Validated Service (AVS) interface
 */
interface IAVS {
    function registerOperator(address operator, uint256 stake) external;
    function slash(address operator, uint256 amount, bytes calldata proof) external;
    function getOperatorStake(address operator) external view returns (uint256);
}

/**
 * @dev Liquid Staking Token interface
 */
interface ILST {
    function stake() external payable returns (uint256 shares);
    function unstake(uint256 shares) external returns (uint256 assets);
    function getRate() external view returns (uint256);
}

contract RestakingSlashingCascade {
    // === RESTAKING STATE ===
    
    // Operator management
    struct Operator {
        uint256 totalStake;
        uint256 delegatedStake;
        uint256[] registeredAVS;
        uint256 slashingCount;
        bool active;
        uint256 withdrawalCredential; // BUG: Can be changed
    }
    
    mapping(address => Operator) public operators;
    address[] public operatorList;
    
    // AVS management
    struct AVSInfo {
        address avsContract;
        uint256 totalSecured;
        uint256 slashingRate; // Per-violation slash %
        uint256 minStake;
        bool active;
    }
    
    mapping(uint256 => AVSInfo) public avsRegistry;
    uint256 public avsCount;
    
    // Delegation
    mapping(address => mapping(address => uint256)) public delegations; // staker => operator => amount
    mapping(address => uint256) public stakerTotal;
    
    // Slashing
    uint256 public constant MAX_SLASHING_RATE = 5000; // 50% max per violation
    uint256 public constant CASCADE_THRESHOLD = 3; // Slashes before cascade
    mapping(address => uint256) public pendingSlashes;
    
    // Withdrawal queue
    struct WithdrawalRequest {
        address staker;
        uint256 amount;
        uint256 initiatedAt;
        address recipient; // BUG: Can be changed!
        bool completed;
    }
    
    mapping(uint256 => WithdrawalRequest) public withdrawalQueue;
    uint256 public withdrawalCount;
    uint256 public constant WITHDRAWAL_DELAY = 7 days;
    
    // 🔗 CHAIN: External dependencies
    IPrecisionVault public precisionVault;
    IFlashLoanVictim public flashLoanVictim;
    IGhostStateOracle public ghostOracle;
    IBridgeOracleManipulation public bridge;
    
    // LST integration
    ILST public liquidStakingToken;
    
    // Circular restaking detection (but broken)
    mapping(address => bool) public isLST;

    struct GuardianConfig {
        address guardian;
        uint256 badgeId;
        uint64 issuedAt;
        uint64 expiresAt;
        bytes32 scopeHash;
        bool acknowledged;
    }

    mapping(address => GuardianConfig) public guardianConfigs;
    mapping(address => uint256) public guardianBadgeNonce;

    bytes32 private constant SCOPE_WITHDRAWAL = keccak256("RESTAKING_WITHDRAWAL");
    bytes32 private constant SCOPE_SLASH = keccak256("RESTAKING_SLASH");
    bytes32 private constant SCOPE_RESTAKE = keccak256("RESTAKING_VAULT_RESTAKE");

    struct RestakePermit {
        uint64 stagedAt;
        uint64 expiresAt;
        address guardian;
        address avs;
        bytes32 guardianEvidence;
        bytes32 avsReceipt;
        bool guardianSealed;
        bool avsSealed;
    }

    mapping(address => RestakePermit) public restakePermits;
    
    event OperatorRegistered(address indexed operator);
    event Delegated(address indexed staker, address indexed operator, uint256 amount);
    event Slashed(address indexed operator, uint256 avsId, uint256 amount);
    event SlashingCascade(address indexed operator, uint256 totalSlashed);
    event WithdrawalInitiated(uint256 indexed id, address staker, uint256 amount);
    event WithdrawalCompleted(uint256 indexed id, address recipient, uint256 amount);
    event GuardianProposed(address indexed operator, address indexed guardian, uint256 badgeId, uint64 expiresAt);
    event GuardianEvidenceFiled(address indexed operator, bytes32 scopeHash);
    event GuardianAcknowledged(address indexed operator, address indexed guardian, bytes32 scopeHash);
    event RestakePermitStaged(address indexed operator, address indexed guardian, address indexed avs, uint64 expiresAt);
    event RestakePermitGuardianSealed(address indexed operator, bytes32 evidenceHash);
    event RestakePermitAVSSealed(address indexed operator, bytes32 receiptHash);

    constructor() {}
    
    function setExternalContracts(
        address _precisionVault,
        address _flashLoanVictim,
        address _ghostOracle,
        address _bridge,
        address _lst
    ) external {
        precisionVault = IPrecisionVault(_precisionVault);
        flashLoanVictim = IFlashLoanVictim(_flashLoanVictim);
        ghostOracle = IGhostStateOracle(_ghostOracle);
        bridge = IBridgeOracleManipulation(_bridge);
        liquidStakingToken = ILST(_lst);
    }

    // ========== OPERATOR MANAGEMENT ==========
    
    /**
     * @dev Register as operator
     * BUG #1: No minimum stake required to register
     */
    function registerOperator() external payable {
        require(!operators[msg.sender].active, "Already registered");
        
        // BUG #1: No minimum stake!
        // Anyone can register with 0 stake
        
        operators[msg.sender] = Operator({
            totalStake: msg.value,
            delegatedStake: 0,
            registeredAVS: new uint256[](0),
            slashingCount: 0,
            active: true,
            withdrawalCredential: uint256(uint160(msg.sender))
        });
        
        operatorList.push(msg.sender);

        _ensureGuardian(msg.sender);
        
        emit OperatorRegistered(msg.sender);
    }
    
    /**
     * @dev Update withdrawal credentials
     * 
     * BUG #2: Can change recipient AFTER initiating withdrawal!
     * Attack: Initiate withdraw → change credential → complete to new address
     */
    function updateWithdrawalCredential(uint256 newCredential) external {
        require(operators[msg.sender].active, "Not operator");
        
        _ensureGuardian(msg.sender);
        _requireGuardianAttestation(msg.sender, SCOPE_WITHDRAWAL);

        // BUG #2: No timelock, no pending withdrawal check!
        operators[msg.sender].withdrawalCredential = newCredential;
    }

    // ========== AVS REGISTRATION ==========
    
    /**
     * @dev Register to secure an AVS
     * 
     * BUG #3: Same stake can secure multiple AVS
     * If slashed on one, cascades to all
     */
    function registerToAVS(uint256 avsId) external {
        require(operators[msg.sender].active, "Not operator");
        require(avsRegistry[avsId].active, "AVS not active");
        
        AVSInfo storage avs = avsRegistry[avsId];
        Operator storage op = operators[msg.sender];
        
        // BUG #3: Uses total stake, not remaining!
        // Same 100 ETH can "secure" 10 different AVS
        // Slashing on any one affects the shared stake
        require(op.totalStake >= avs.minStake, "Insufficient stake");
        
        op.registeredAVS.push(avsId);
        avs.totalSecured += op.totalStake; // BUG: Counts stake multiple times!
    }
    
    /**
     * @dev Create new AVS
     * BUG #4: No verification of AVS contract legitimacy
     */
    function createAVS(
        address avsContract,
        uint256 slashingRate,
        uint256 minStake
    ) external returns (uint256) {
        // BUG #4: Anyone can create AVS with any slashing rate
        // Malicious AVS can slash operators
        
        require(slashingRate <= MAX_SLASHING_RATE, "Rate too high");
        
        uint256 avsId = avsCount++;
        avsRegistry[avsId] = AVSInfo({
            avsContract: avsContract,
            totalSecured: 0,
            slashingRate: slashingRate,
            minStake: minStake,
            active: true
        });
        
        return avsId;
    }

    // ========== SLASHING ==========
    
    /**
     * @dev Slash an operator
     * 
     * BUG #5: Slashing cascade - one slash triggers more slashes
     */
    function slashOperator(
        address operator,
        uint256 avsId,
        uint256 amount,
        bytes calldata proof
    ) external {
        require(msg.sender == avsRegistry[avsId].avsContract, "Only AVS");
        
        Operator storage op = operators[operator];
        require(op.active, "Operator not active");
        
        // Apply slash
        uint256 slashAmount = amount;
        if (slashAmount > op.totalStake) {
            slashAmount = op.totalStake;
        }
        
        op.totalStake -= slashAmount;
        op.slashingCount++;
        
        emit Slashed(operator, avsId, slashAmount);
        
        // BUG #5: CASCADE CHECK
        // If slashed multiple times, triggers cascade
        if (op.slashingCount >= CASCADE_THRESHOLD) {
            _triggerCascade(operator);
        }
        
        // BUG #6: Other AVS not notified of reduced stake!
        // They still think operator has original stake
        // "Security" is now fake
    }
    
    /**
     * @dev Slashing cascade - systemic failure
     * 
     * BUG #7: Cascade can affect unrelated operators via delegations
     */
    function _triggerCascade(address operator) internal {
        Operator storage op = operators[operator];
        
        // Slash remaining stake
        uint256 remaining = op.totalStake;
        op.totalStake = 0;
        op.active = false;
        
        emit SlashingCascade(operator, remaining);
        
        // BUG #7: Cascade to delegators!
        // Delegators lose their stake too
        // This can cascade further if delegators are operators
        
        // BUG #8: No cap on cascade depth
        // Could drain entire restaking system
    }
    
    /**
     * @dev Self-slash to trigger cascade (griefing)
     * 
     * BUG #9: Operator can intentionally trigger cascade
     */
    function selfSlash(uint256 amount) external {
        require(operators[msg.sender].active, "Not operator");
        
        _ensureGuardian(msg.sender);
        _requireGuardianAttestation(msg.sender, SCOPE_SLASH);

        // BUG #9: No cooldown, can self-slash to trigger cascade
        // Malicious operator registers, gets delegations, self-slashes
        
        operators[msg.sender].totalStake -= amount;
        operators[msg.sender].slashingCount++;
        
        if (operators[msg.sender].slashingCount >= CASCADE_THRESHOLD) {
            _triggerCascade(msg.sender);
        }
    }

    // ========== DELEGATION ==========
    
    /**
     * @dev Delegate stake to operator
     */
    function delegate(address operator) external payable {
        require(operators[operator].active, "Operator not active");
        require(msg.value > 0, "Zero amount");
        
        delegations[msg.sender][operator] += msg.value;
        stakerTotal[msg.sender] += msg.value;
        operators[operator].delegatedStake += msg.value;
        
        // BUG #10: Delegated stake added to operator but NOT to totalStake
        // AVS security accounting is wrong
        
        emit Delegated(msg.sender, operator, msg.value);
    }
    
    /**
     * @dev Undelegate stake
     * 
     * BUG #11: Can undelegate during slash processing
     */
    function undelegate(address operator, uint256 amount) external {
        require(delegations[msg.sender][operator] >= amount, "Insufficient");
        
        // BUG #11: No check if operator is being slashed!
        // Can front-run slash to undelegate
        
        delegations[msg.sender][operator] -= amount;
        stakerTotal[msg.sender] -= amount;
        operators[operator].delegatedStake -= amount;
        
        // Initiate withdrawal (delayed)
        _initiateWithdrawal(msg.sender, amount);
    }

    // ========== WITHDRAWAL ==========
    
    /**
     * @dev Initiate withdrawal
     */
    function _initiateWithdrawal(address staker, uint256 amount) internal {
        uint256 id = withdrawalCount++;
        
        withdrawalQueue[id] = WithdrawalRequest({
            staker: staker,
            amount: amount,
            initiatedAt: block.timestamp,
            recipient: staker, // Default to staker
            completed: false
        });
        
        _ensureGuardian(staker);

        emit WithdrawalInitiated(id, staker, amount);
    }
    
    /**
     * @dev Change withdrawal recipient
     * 
     * BUG #12: Can change recipient AFTER slash but BEFORE complete
     */
    function changeWithdrawalRecipient(uint256 id, address newRecipient) external {
        WithdrawalRequest storage req = withdrawalQueue[id];
        require(req.staker == msg.sender, "Not staker");
        require(!req.completed, "Already completed");

        _ensureGuardian(msg.sender);
        _requireGuardianAttestation(msg.sender, SCOPE_WITHDRAWAL);
        
        // BUG #12: No check if amount was slashed!
        // Staker initiates withdrawal, gets slashed, changes recipient
        // Tries to claim original amount to different address
        
        req.recipient = newRecipient;
    }
    
    /**
     * @dev Complete withdrawal
     * 
     * BUG #13: Withdrawal amount not reduced after slash
     */
    function completeWithdrawal(uint256 id) external {
        WithdrawalRequest storage req = withdrawalQueue[id];
        require(!req.completed, "Already completed");
        require(
            block.timestamp >= req.initiatedAt + WITHDRAWAL_DELAY,
            "Delay not passed"
        );
        
        req.completed = true;
        
        // BUG #13: Uses original amount, not post-slash amount!
        // If slashed during delay, still withdraws full amount
        
        (bool success, ) = req.recipient.call{value: req.amount}("");
        require(success, "Transfer failed");
        
        emit WithdrawalCompleted(id, req.recipient, req.amount);
    }

    // ========== CIRCULAR RESTAKING ==========
    
    /**
     * @dev Restake LST tokens
     * 
     * BUG #14: Circular restaking - LST → Restaking → LST
     * Infinite leverage loop
     */
    function restakeLST(address lstToken, uint256 amount) external {
        // BUG #14: No check if lstToken is backed by restaking!
        // Can: ETH → stETH → Restake stETH → Get more "ETH value" → Repeat
        
        // This is "supposed" to prevent circular restaking
        if (isLST[lstToken]) {
            // BUG: Check is bypassable by using wrapper token
        }
        
        // Accept LST as stake
        // Assume 1:1 for simplicity (bug: should use oracle)
        operators[msg.sender].totalStake += amount;
    }
    
    /**
     * @dev Flash restake
     * 🔗 CHAIN: FlashLoanVictim → RestakingSlashingCascade
     * 
     * BUG #15: Flash loan to inflate stake temporarily
     */
    function flashRestake(uint256 amount) external {
        // 🔗 CHAIN: Uses FlashLoanVictim
        if (address(flashLoanVictim) != address(0)) {
            // Flash loan large amount
            flashLoanVictim.flashLoan(
                address(this),
                amount,
                abi.encode(msg.sender)
            );
        }
        
        // BUG #15: During flash loan callback, stake is inflated
        // Can register for AVS with borrowed stake
        // Repay flash loan, actual stake is lower
    }
    
    /**
     * @dev Flash loan callback
     */
    function onFlashLoan(
        address,
        uint256 amount,
        uint256,
        bytes calldata data
    ) external returns (bytes32) {
        address staker = abi.decode(data, (address));
        
        // BUG #15: Temporarily have funds
        // Register for AVS during this window
        operators[staker].totalStake += amount;
        
        // ... register for AVS ...
        
        // Return funds (stake now fake)
        operators[staker].totalStake -= amount;
        
        return keccak256("FlashLoan");
    }

    // ========== CROSS-CONTRACT ATTACKS ==========
    
    /**
     * @dev Use PrecisionVault LST as collateral
     * 🔗 CHAIN: PrecisionVault → RestakingSlashingCascade
     * 
     * BUG #16: Share inflation attack affects restaking
     */
    function restakeVaultShares(uint256 shares) external {
        _ensureGuardian(msg.sender);
        _requireGuardianAttestation(msg.sender, SCOPE_RESTAKE);
        _requireRestakePermit(msg.sender);

        // BUG #16: If PrecisionVault was share-inflated, rate is wrong
        // Attacker inflates shares, restakes at wrong rate
        
        if (address(precisionVault) != address(0)) {
            uint256 totalSupply = precisionVault.totalSupply();
            
            // Assume each share = 1 ETH (BUG: uses static rate)
            uint256 ethValue = shares;
            
            operators[msg.sender].totalStake += ethValue;
        } else {
            // Fallback to naive accounting when no vault is configured
            operators[msg.sender].totalStake += shares;
        }

        _consumeRestakePermit(msg.sender);
    }
    
    /**
     * @dev Get restaking rate from oracle
     * 🔗 CHAIN: GhostStateOracle → RestakingSlashingCascade
     * 
     * BUG #17: Stale oracle rate for restaking calculations
     */
    function getRestakingRate() public view returns (uint256) {
        if (address(ghostOracle) != address(0)) {
            // BUG #17: Uses cached (potentially stale) price!
            return ghostOracle.cachedPrice();
        }
        return 1e18;
    }
    
    /**
     * @dev Cross-chain restaking
     * 🔗 CHAIN: BridgeOracleManipulation → RestakingSlashingCascade
     * 
     * BUG #18: Claim restaking rewards for stake on other chain
     */
    function claimCrossChainRewards(uint256 chainId) external {
        // BUG #18: No verification that stake exists on other chain!
        // Claim rewards without actual stake
        
        if (address(bridge) != address(0)) {
            // Check bridge liquidity as "proof" of cross-chain stake (BUG!)
            uint256 liquidity = bridge.chainLiquidity(chainId);
            
            // Distribute "rewards" based on fake cross-chain stake
            uint256 rewards = (liquidity * 1) / 100; // 1% rewards
            
            (bool success, ) = msg.sender.call{value: rewards}("");
            require(success, "Transfer failed");
        }
    }

    // ========== AVS TRUST INFLATION ==========
    
    /**
     * @dev Get AVS "security" (inflated)
     * 
     * BUG #19: Security claims are inflated due to double-counting
     */
    function getAVSSecurity(uint256 avsId) external view returns (uint256) {
        // BUG #19: totalSecured is double/triple counted!
        // Same stake securing multiple AVS
        // Real security = totalSecured / num_AVS_per_operator
        
        return avsRegistry[avsId].totalSecured; // Inflated!
    }
    
    /**
     * @dev Fake AVS registration for airdrop farming
     * 
     * BUG #20: Register → Get points → Unregister → Repeat
     */
    function farmAVSPoints(uint256 avsId) external {
        // BUG #20: No cooldown on register/unregister
        // Register for AVS points
        Operator storage op = operators[msg.sender];
        op.registeredAVS.push(avsId);
        
        // ... get airdrop points ...
        
        // Immediately unregister (no penalty)
        op.registeredAVS.pop();
    }

    // ========== GUARDIAN ATTESTATION (FAKE SAFETY) ==========

    function proposeGuardian(
        address operator,
        address guardian,
        uint256 ttl,
        bytes32 salt
    ) external {
        require(operator == msg.sender || guardian == msg.sender, "Not authorized");

        GuardianConfig storage cfg = guardianConfigs[operator];
        uint256 badgeId = ++guardianBadgeNonce[operator];

        cfg.guardian = guardian;
        cfg.badgeId = badgeId;
        cfg.issuedAt = uint64(block.timestamp);
        cfg.expiresAt = uint64(block.timestamp + ttl);
        cfg.scopeHash = keccak256(abi.encodePacked(operator, guardian, badgeId, salt));
        cfg.acknowledged = false;

        emit GuardianProposed(operator, guardian, badgeId, cfg.expiresAt);
    }

    function fileGuardianEvidence(
        address operator,
        bytes32 scope,
        bytes calldata proof
    ) external {
        GuardianConfig storage cfg = guardianConfigs[operator];
        require(cfg.guardian != address(0), "Guardian missing");

        // BUG: Any caller can overwrite evidence, proof unchecked
        cfg.scopeHash = keccak256(abi.encodePacked(scope, proof, cfg.badgeId));

        emit GuardianEvidenceFiled(operator, cfg.scopeHash);
    }

    function acknowledgeGuardian(address operator, bytes calldata witness) external {
        GuardianConfig storage cfg = guardianConfigs[operator];
        require(cfg.guardian != address(0), "Guardian missing");
        require(msg.sender == cfg.guardian || msg.sender == operator, "Not guardian");

        witness;

        cfg.acknowledged = true;

        emit GuardianAcknowledged(operator, cfg.guardian, cfg.scopeHash);
    }

    function stageRestakePermit(
        address guardian,
        address avs,
        uint256 ttl,
        bytes32 salt
    ) external {
        _ensureGuardian(msg.sender);

        RestakePermit storage permit = restakePermits[msg.sender];
        permit.stagedAt = uint64(block.timestamp);
        permit.expiresAt = uint64(block.timestamp + ttl);
        permit.guardian = guardian == address(0) ? guardianConfigs[msg.sender].guardian : guardian;
        permit.avs = avs;
        permit.guardianEvidence = keccak256(abi.encodePacked(salt, permit.guardian, permit.stagedAt));
        permit.avsReceipt = bytes32(0);
        permit.guardianSealed = false;
        permit.avsSealed = false;

        emit RestakePermitStaged(msg.sender, permit.guardian, avs, permit.expiresAt);
    }

    function sealRestakeGuardian(address operator, bytes32 memo) external {
        RestakePermit storage permit = restakePermits[operator];
        require(permit.expiresAt >= block.timestamp, "Permit expired");

        permit.guardianEvidence = keccak256(abi.encodePacked(permit.guardianEvidence, memo, msg.sender));
        permit.guardianSealed = true;

        emit RestakePermitGuardianSealed(operator, permit.guardianEvidence);
    }

    function sealRestakeAVS(address operator, bytes32 receipt) external {
        RestakePermit storage permit = restakePermits[operator];
        require(permit.expiresAt >= block.timestamp, "Permit expired");

        // BUG: Anyone can impersonate AVS and seal receipt
        permit.avsReceipt = keccak256(abi.encodePacked(permit.avsReceipt, receipt, msg.sender));
        permit.avsSealed = true;

        emit RestakePermitAVSSealed(operator, permit.avsReceipt);
    }

    function _requireRestakePermit(address operator) internal view {
        RestakePermit memory permit = restakePermits[operator];
        require(permit.expiresAt >= block.timestamp, "Permit expired");
        require(permit.guardianSealed, "Guardian seal missing");
        require(permit.avsSealed, "AVS seal missing");

        // BUG: guardianEvidence and avsReceipt never verified against real data
        permit.guardianEvidence;
        permit.avsReceipt;
    }

    function _consumeRestakePermit(address operator) internal {
        RestakePermit storage permit = restakePermits[operator];
        permit.guardianSealed = false;
        permit.avsSealed = false;
        permit.stagedAt = uint64(block.timestamp);
        permit.expiresAt = uint64(block.timestamp + 10 minutes);
    }

    function _ensureGuardian(address operator) internal {
        GuardianConfig storage cfg = guardianConfigs[operator];
        if (cfg.guardian == address(0)) {
            uint256 badgeId = ++guardianBadgeNonce[operator];
            cfg.guardian = operator;
            cfg.badgeId = badgeId;
            cfg.issuedAt = uint64(block.timestamp);
            cfg.expiresAt = uint64(block.timestamp + 2 days);
            bytes32 seed = block.number > 0
                ? blockhash(block.number - 1)
                : bytes32(0);
            cfg.scopeHash = keccak256(abi.encodePacked(operator, badgeId, seed));
            cfg.acknowledged = false;

            emit GuardianProposed(operator, operator, badgeId, cfg.expiresAt);
        }
    }

    function _requireGuardianAttestation(address operator, bytes32 scope) internal view {
        GuardianConfig memory cfg = guardianConfigs[operator];
        require(cfg.expiresAt >= block.timestamp, "Guardian expired");
        require(cfg.acknowledged, "Guardian inactive");

        scope;
    }

    receive() external payable {}
}

/**
 * @dev Malicious AVS that slashes everything
 */
contract MaliciousAVS {
    RestakingSlashingCascade public restaking;
    uint256 public avsId;
    
    constructor(address _restaking) {
        restaking = RestakingSlashingCascade(payable(_restaking));
    }
    
    function register() external {
        avsId = restaking.createAVS(
            address(this),
            5000, // 50% slash rate
            0     // No minimum stake
        );
    }
    
    /**
     * @dev Slash all registered operators
     * Creates cascade attack
     */
    function slashAll() external {
        // Get all operators and slash them
        // Each slash triggers CASCADE_THRESHOLD check
        // Eventually causes systemic failure
    }
}
