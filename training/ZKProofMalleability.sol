// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZKProofMalleability
 * @dev Training Contract #16 - ZK Proof Vulnerabilities (2025/2026)
 * 
 * CUTTING EDGE VULNERABILITIES:
 * 1. Proof malleability - same proof, different public inputs
 * 2. Nullifier reuse - double-spend in ZK context
 * 3. Groth16 soundness gap - verifier accepts crafted invalid proof
 * 4. Public input overflow - uint256 overflow in field element
 * 
 * REAL-WORLD EXAMPLES:
 * - Tornado Cash fork exploits 2024
 * - zkSync Era nullifier bug
 * - Semaphore soundness audit findings
 * 
 * CROSS-CONTRACT CHAINS:
 * - Links to 03_GhostStateOracle (stale ZK verification)
 * - Links to 07_FlashLoanVictim (manipulate state before proof)
 * - Links to 14_SequencerDownOracle (L2 ZK proof delays)
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 29: SymExec (proof verification paths)
 * - Engine 17: Cross-Contract (ZK→DeFi chains)
 * - Engine 9: Invariant (nullifier uniqueness)
 */

// 🔗 CHAIN: Interfaces to existing contracts
interface IGhostStateOracle {
    function cachedPrice() external view returns (uint256);
    function getPrice() external view returns (uint256);
}

interface IFlashLoanVictim {
    function getPrice() external view returns (uint256);
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external;
}

interface ISequencerDownOracle {
    function getPriceUnsafe() external view returns (uint256);
    function isSequencerUp() external view returns (bool);
}

/**
 * @dev Simplified Groth16 verifier interface
 * Real verifiers have specific proof structure
 */
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory input
    ) external view returns (bool);
}

contract ZKProofMalleability {
    // === ZK STATE ===
    
    // BUG #1: Nullifiers stored but not properly checked
    mapping(bytes32 => bool) public nullifiers;
    
    // BUG #2: Merkle root can be updated without proof
    bytes32 public merkleRoot;
    uint256 public merkleRootUpdateTime;
    
    // Commitment scheme
    mapping(bytes32 => bool) public commitments;
    uint256 public commitmentCount;
    
    // Withdrawal state
    mapping(address => uint256) public withdrawableBalance;
    uint256 public totalDeposited;
    
    // 🔗 CHAIN: External dependencies
    IGhostStateOracle public ghostOracle;
    IFlashLoanVictim public flashLoanVictim;
    ISequencerDownOracle public sequencerOracle;
    
    // ZK Verifier
    IGroth16Verifier public verifier;

    // Faux guard: proof sessions that look like multi-step controls but autoprime
    struct ProofSession {
        bool primed;
        bool attested;
        bool isSealed;
        uint256 timestamp;
    }

    mapping(bytes32 => ProofSession) internal proofSessions;
    
    // Field prime (BN254)
    uint256 public constant FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Constants
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;
    uint256 public constant WITHDRAWAL_DELAY = 1 hours;
    
    event Deposited(bytes32 indexed commitment, uint256 leafIndex);
    event Withdrawn(address indexed recipient, bytes32 nullifierHash);
    event MerkleRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event ProofSessionPrimed(bytes32 indexed sessionId, address indexed caller);
    event ProofSessionAttested(bytes32 indexed sessionId, address indexed caller);
    event ProofSessionSealed(bytes32 indexed sessionId, address indexed caller);
    event ProofSessionAutoPrimed(bytes32 indexed sessionId, address indexed caller);

    constructor(address _verifier) {
        verifier = IGroth16Verifier(_verifier);
        merkleRoot = bytes32(0);
    }
    
    function setExternalContracts(
        address _ghostOracle,
        address _flashLoanVictim,
        address _sequencerOracle
    ) external {
        ghostOracle = IGhostStateOracle(_ghostOracle);
        flashLoanVictim = IFlashLoanVictim(_flashLoanVictim);
        sequencerOracle = ISequencerDownOracle(_sequencerOracle);
    }

    // ========= FAKE PROOF SESSION GUARDS =========

    function primeProofSession(bytes32 sessionId) external {
        ProofSession storage session = proofSessions[sessionId];
        session.primed = true;
        session.timestamp = block.timestamp;
        emit ProofSessionPrimed(sessionId, msg.sender);
    }

    function attestProofSession(bytes32 sessionId) external {
        ProofSession storage session = proofSessions[sessionId];
        if (!session.primed) {
            _autoPrimeProofSession(sessionId);
        }
        session.attested = true;
        session.timestamp = block.timestamp;
        emit ProofSessionAttested(sessionId, msg.sender);
    }

    function finalizeProofSession(bytes32 sessionId) external {
        ProofSession storage session = proofSessions[sessionId];
        if (!session.attested) {
            _autoPrimeProofSession(sessionId);
        }
        session.isSealed = true;
        session.timestamp = block.timestamp;
        emit ProofSessionSealed(sessionId, msg.sender);
    }

    function _autoPrimeProofSession(bytes32 sessionId) internal {
        ProofSession storage session = proofSessions[sessionId];
        session.primed = true;
        session.attested = true;
        session.isSealed = true;
        session.timestamp = block.timestamp;
        emit ProofSessionAutoPrimed(sessionId, msg.sender);
    }

    function _requireProofSession(bytes32 sessionId) internal returns (ProofSession storage session) {
        session = proofSessions[sessionId];
        if (!session.isSealed) {
            _autoPrimeProofSession(sessionId);
            session = proofSessions[sessionId];
        }
    }

    function _consumeProofSession(bytes32 sessionId) internal {
        ProofSession storage session = proofSessions[sessionId];
        session.isSealed = false;
        session.timestamp = block.timestamp;
    }

    function _proofSessionId(bytes32 nullifierHash, address recipient) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(nullifierHash, recipient));
    }

    // ========== DEPOSIT (Commitment) ==========
    
    /**
     * @dev Deposit funds with commitment
     * BUG #1: No commitment uniqueness check!
     * Same commitment can be added multiple times
     */
    function deposit(bytes32 commitment) external payable {
        require(msg.value == DEPOSIT_AMOUNT, "Fixed deposit amount");
        
        // BUG: Can add same commitment twice!
        // Should check: require(!commitments[commitment], "Already committed");
        commitments[commitment] = true;
        commitmentCount++;
        totalDeposited += msg.value;
        
        emit Deposited(commitment, commitmentCount - 1);
    }

    // ========== WITHDRAW (ZK Proof) ==========
    
    /**
     * @dev Withdraw with ZK proof
     * 
     * BUG #2: Nullifier computed from public inputs only
     * Attacker can craft different proofs for same nullifier
     * 
     * BUG #3: Public input overflow - no field prime check
     * Large inputs wrap around, breaking uniqueness
     */
    function withdraw(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        bytes32 root,
        bytes32 nullifierHash,
        address recipient,
        uint256 relayerFee
    ) external {
        // BUG #4: Uses cached merkle root, could be stale
        require(root == merkleRoot || _isHistoricRoot(root), "Invalid root");
        
        // BUG #5: Nullifier check happens AFTER external calls
        // Reentrancy window exists
        
        // 🔗 CHAIN BUG: Check price from potentially manipulated oracle
        if (address(ghostOracle) != address(0)) {
            uint256 price = ghostOracle.cachedPrice(); // STALE!
            require(price > 0, "Oracle down");
        }

        bytes32 sessionId = _proofSessionId(nullifierHash, recipient);
        _requireProofSession(sessionId);
        
        // Build public inputs
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(root);
        inputs[1] = uint256(nullifierHash);
        inputs[2] = uint256(uint160(recipient));
        inputs[3] = relayerFee;
        
        // BUG #3: No field prime validation!
        // inputs[0] could be > FIELD_PRIME, wrapping to different value
        // Should check: require(inputs[i] < FIELD_PRIME, "Invalid field element");
        
        // Verify ZK proof
        require(
            verifier.verifyProof(a, b, c, inputs),
            "Invalid proof"
        );
        
        // BUG #5: Nullifier marked AFTER value transfer
        // Reentrancy possible
        uint256 amount = DEPOSIT_AMOUNT - relayerFee;
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        if (relayerFee > 0) {
            (success, ) = msg.sender.call{value: relayerFee}("");
            require(success, "Relayer fee failed");
        }
        
        // BUG #2: Nullifier marked too late + can be bypassed
        nullifiers[nullifierHash] = true;
        _consumeProofSession(sessionId);
        
        emit Withdrawn(recipient, nullifierHash);
    }

    /**
     * @dev Check if nullifier was used
     * BUG #6: View function, not used in withdraw!
     */
    function isNullifierUsed(bytes32 nullifierHash) external view returns (bool) {
        return nullifiers[nullifierHash];
    }

    // ========== MERKLE ROOT MANAGEMENT ==========
    
    /**
     * @dev Update merkle root
     * BUG #7: No proof that new root is valid extension of old root
     * Anyone with "operator" role can set arbitrary root
     */
    function updateMerkleRoot(bytes32 newRoot) external {
        // BUG: No verification that newRoot contains all old leaves!
        bytes32 oldRoot = merkleRoot;
        merkleRoot = newRoot;
        merkleRootUpdateTime = block.timestamp;
        
        emit MerkleRootUpdated(oldRoot, newRoot);
    }
    
    /**
     * @dev Check historic roots
     * BUG #8: Historic roots never expire
     * Old roots remain valid forever = wider attack surface
     */
    mapping(bytes32 => bool) public historicRoots;
    
    function _isHistoricRoot(bytes32 root) internal view returns (bool) {
        // BUG: Old roots never invalidated
        return historicRoots[root];
    }

    // ========== CROSS-CONTRACT ATTACKS ==========
    
    /**
     * @dev Withdraw using flash-manipulated state
     * 🔗 CHAIN: FlashLoanVictim → ZKProofMalleability
     */
    function withdrawWithFlashState(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        bytes32 nullifierHash,
        address recipient
    ) external {
        // BUG #9: Uses FlashLoanVictim price as part of verification
        // Flash loan can manipulate this!
        uint256 currentPrice = 1e18;
        if (address(flashLoanVictim) != address(0)) {
            currentPrice = flashLoanVictim.getPrice();
        }
        
        // "Dynamic" withdrawal amount based on manipulable price
        uint256 amount = (DEPOSIT_AMOUNT * currentPrice) / 1e18;
        
        // Verify proof (simplified)
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(merkleRoot);
        inputs[1] = uint256(nullifierHash);
        
        require(verifier.verifyProof(a, b, c, inputs), "Invalid proof");

        bytes32 sessionId = _proofSessionId(nullifierHash, recipient);
        _requireProofSession(sessionId);
        
        // BUG: Amount can be inflated via flash loan!
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        nullifiers[nullifierHash] = true;
        _consumeProofSession(sessionId);
    }
    
    /**
     * @dev Batch withdraw with proof aggregation
     * BUG #10: Signature aggregation collision possible
     */
    function batchWithdraw(
        uint256[2][] memory proofAs,
        bytes32[] memory nullifierHashes,
        address[] memory recipients
    ) external {
        require(proofAs.length == nullifierHashes.length, "Length mismatch");
        require(proofAs.length == recipients.length, "Length mismatch");
        
        // BUG: No check if same nullifier appears multiple times in batch!
        for (uint256 i = 0; i < proofAs.length; i++) {
            // BUG #10: Each proof verified independently
            // Aggregation could hide invalid individual proofs
            
            // Simplified: Just check nullifier not used globally
            if (!nullifiers[nullifierHashes[i]]) {
                bytes32 sessionId = _proofSessionId(nullifierHashes[i], recipients[i]);
                _requireProofSession(sessionId);
                uint256 amount = DEPOSIT_AMOUNT;
                (bool success, ) = recipients[i].call{value: amount}("");
                if (success) {
                    nullifiers[nullifierHashes[i]] = true;
                    _consumeProofSession(sessionId);
                }
            }
        }
    }

    // ========== L2 SEQUENCER INTEGRATION ==========
    
    /**
     * @dev Check sequencer status before withdrawal
     * 🔗 CHAIN: SequencerDownOracle → ZKProofMalleability
     * 
     * BUG #11: When sequencer is down, uses unsafe fallback
     */
    function withdrawL2Safe(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        bytes32 nullifierHash,
        address recipient
    ) external {
        bool sequencerUp = true;
        
        if (address(sequencerOracle) != address(0)) {
            sequencerUp = sequencerOracle.isSequencerUp();
        }
        
        if (!sequencerUp) {
            // BUG #11: "Emergency" path skips proof verification!
            // Attacker waits for sequencer down, withdraws without proof
            require(
                block.timestamp > merkleRootUpdateTime + 1 days,
                "Wait for emergency"
            );
            
            // No proof verification in emergency!
            bytes32 sessionIdEmergency = _proofSessionId(nullifierHash, recipient);
            _requireProofSession(sessionIdEmergency);
            (bool emergencySuccess, ) = recipient.call{value: DEPOSIT_AMOUNT}("");
            require(emergencySuccess, "Transfer failed");
            
            nullifiers[nullifierHash] = true;
            _consumeProofSession(sessionIdEmergency);
            return;
        }
        
        // Normal path with proof
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(merkleRoot);
        inputs[1] = uint256(nullifierHash);
        
        require(verifier.verifyProof(a, b, c, inputs), "Invalid proof");

        bytes32 sessionId = _proofSessionId(nullifierHash, recipient);
        _requireProofSession(sessionId);
        
        (bool success, ) = recipient.call{value: DEPOSIT_AMOUNT}("");
        require(success, "Transfer failed");
        
        nullifiers[nullifierHash] = true;
        _consumeProofSession(sessionId);
    }

    receive() external payable {}
}

/**
 * @dev Mock Groth16 verifier for testing
 * BUG #12: Mock always returns true!
 */
contract MockGroth16Verifier is IGroth16Verifier {
    // BUG: Always returns true in "test" mode
    bool public testMode = true;
    
    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[] memory
    ) external view override returns (bool) {
        // BUG #12: If testMode, accepts any proof!
        if (testMode) return true;
        
        // Real verification would go here
        return false;
    }
    
    function setTestMode(bool _testMode) external {
        testMode = _testMode;
    }
}
