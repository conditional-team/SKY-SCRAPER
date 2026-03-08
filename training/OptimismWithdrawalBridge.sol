// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title OptimismWithdrawalBridge
 * @dev Training Contract #69 - Optimism Withdrawal Verification + Cross-Domain Messaging (2025/2026)
 *
 * CUTTING EDGE VULNERABILITIES:
 * 1.  Merkle proof bypass via crafted trie nodes
 * 2.  Cross-chain message replay without nonce protection
 * 3.  Output root used before finalization
 * 4.  Withdrawal re-proving / proof reuse
 * 5.  Cross-domain sender spoofing
 * 6.  Message queue manipulation
 * 7.  Failed message re-execution
 * 8.  Storage proof forgery via encodePacked collision
 *
 * TARGETED PATTERNS (31):
 *   WD-01 through WD-15 (withdrawal-verifier crate)
 *   MSG-01 through MSG-16 (l2-message-checker crate)
 *
 * REAL-WORLD EXAMPLES:
 * - Optimism Portal (L1 withdrawal finalization)
 * - L2CrossDomainMessenger (OP Stack)
 * - L2ToL1MessagePasser (Bedrock)
 * - Wintermute Optimism bridge exploit (2022) — replay with missing nonce
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to OptimismDisputeGame (#68) — dispute resolution for output roots
 * - Links to 51_CrossChainMessaging — cross-chain message patterns
 * - Links to 35_BridgeCrossChainAdvanced — bridge attack patterns
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 25: Finality (output root finalization, proof maturity)
 * - Engine 17: Cross-Contract (L1-L2 message passing)
 * - Engine 1:  Reentrancy (callback reentrancy via relayed messages)
 * - Engine 15: Storage (Merkle/storage proof verification)
 */

// ========== LIBRARIES ==========

/// @dev Secure Merkle Trie for inclusion proofs
library SecureMerkleTrie {
    /**
     * @dev Verify Merkle inclusion proof
     * WD-01: This verification can be bypassed with crafted nodes
     */
    function verifyInclusionProof(
        bytes memory _key,
        bytes memory _value,
        bytes[] memory _proof,
        bytes32 _root
    ) internal pure returns (bool) {
        // BUG: Simplified mock — real impl checks RLP-encoded trie path
        // WD-01: Not checking proof node length / RLP validity
        if (_proof.length == 0) return false;

        // BUG: Only checks first proof node against root, not full path
        return keccak256(_proof[0]) == _root;
    }
}

/// @dev RLP encoding helpers
library RLPWriter {
    function writeBytes(bytes memory _in) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x80 + _in.length), _in);
    }
}

// ========== TYPES ==========

/// @dev Output root proof structure
struct OutputRootProof {
    bytes32 version;
    bytes32 stateRoot;
    bytes32 messagePasserStorageRoot;
    bytes32 latestBlockhash;
}

/// @dev Withdrawal transaction from L2
struct WithdrawalTransaction {
    uint256 nonce;
    address sender;
    address target;
    uint256 value;
    uint256 gasLimit;
    bytes data;
}

/// @dev Proven withdrawal record
struct ProvenWithdrawal {
    bytes32 outputRoot;
    uint128 timestamp;
    uint128 l2OutputIndex;
}

/// @dev L2 Output proposal
struct L2Output {
    bytes32 outputRoot;
    uint128 timestamp;
    uint128 l2BlockNumber;
}

// ========== INTERFACES ==========

/// @dev L2OutputOracle interface
interface IL2OutputOracle {
    function getL2Output(uint256 _l2OutputIndex) external view returns (L2Output memory);
    function proposeL2Output(bytes32 _outputRoot, uint256 _l2BlockNumber, bytes32 _l1Blockhash, uint256 _l1BlockNumber) external;
    function latestOutputIndex() external view returns (uint256);
    function FINALIZATION_PERIOD_SECONDS() external view returns (uint256);
}

/// @dev SystemConfig interface
interface ISystemConfig {
    function gasLimit() external view returns (uint64);
}

// ========== MAIN CONTRACT ==========

contract OptimismWithdrawalBridge {
    using SecureMerkleTrie for bytes;

    // ========== CONSTANTS ==========

    // WD-06 / TIME-08: Finalization period too short
    uint256 public constant FINALIZATION_PERIOD_SECONDS = 2 days;

    // WD-04: Proof maturity delay — can be circumvented
    uint256 public constant PROOF_MATURITY_DELAY_SECONDS = 7 days;

    // MSG-06: Gas limit for message relay
    uint256 public constant MIN_GAS_LIMIT = 21000;

    // MSG-01: Replay protection version
    uint16 public constant MESSAGE_VERSION = 1;

    // ========== STATE ==========

    /// @dev L2OutputOracle reference
    IL2OutputOracle public l2Oracle;

    /// @dev Proven withdrawals mapping
    // WD-09: Can be re-proven (overwritten)
    mapping(bytes32 => ProvenWithdrawal) public provenWithdrawals;

    /// @dev Finalized withdrawals
    // WD-10: Not properly marked as finalized
    mapping(bytes32 => bool) public finalizedWithdrawals;

    /// @dev L2 Output proposals
    L2Output[] public l2Outputs;

    /// @dev The authorized proposer
    // WD-05: Proposer authorization can be bypassed
    address public proposer;

    /// @dev Cross-domain sender for current message
    // MSG-02 / MSG-12: Can be spoofed
    address internal xDomainMsgSender;

    /// @dev Cross-domain message nonce
    uint256 public msgNonce;

    /// @dev Failed messages — can be re-executed
    // MSG-07: Failed messages re-execution
    mapping(bytes32 => bool) public failedMessages;

    /// @dev Successfully relayed messages
    // MSG-08: Tracking can be bypassed
    mapping(bytes32 => bool) public successfulMessages;

    /// @dev Message hash to sender mapping
    mapping(bytes32 => address) public messageSenders;

    /// @dev Reentrancy lock (but not properly used)
    bool private _entered;

    // ========== EVENTS ==========

    event WithdrawalProven(bytes32 indexed withdrawalHash, address indexed from, address indexed to);
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success);
    event OutputProposed(bytes32 indexed outputRoot, uint256 indexed l2BlockNumber, uint256 l2OutputIndex);
    event SentMessage(address indexed target, address sender, bytes message, uint256 messageNonce, uint256 gasLimit);
    event RelayedMessage(bytes32 indexed msgHash);
    event FailedRelayedMessage(bytes32 indexed msgHash);
    event MessagePassed(uint256 indexed nonce, address indexed sender, address indexed target, uint256 value, uint256 gasLimit, bytes data, bytes32 withdrawalHash);

    // ========== CONSTRUCTOR ==========

    constructor(address _l2Oracle, address _proposer) {
        l2Oracle = IL2OutputOracle(_l2Oracle);
        proposer = _proposer;
        xDomainMsgSender = address(0);
    }

    // ================================================================
    //                    WITHDRAWAL VERIFICATION
    // ================================================================

    /**
     * @dev Prove a withdrawal transaction
     *
     * WD-01: Merkle proof bypass — SecureMerkleTrie.verifyInclusionProof not robust
     * WD-02: encodePacked length extension — hash collision possible
     * WD-03: Output root used without checking finalization
     * WD-04: Output root used before finalization period
     * WD-11: withdrawalHash missing unique ID fields
     */
    function proveWithdrawalTransaction(
        WithdrawalTransaction memory _tx,
        uint256 _l2OutputIndex,
        OutputRootProof calldata _outputRootProof,
        bytes[] calldata _withdrawalProof
    ) external {
        // WD-03: Output root NOT checked against L2OutputOracle!
        // BUG: Should verify l2Oracle.getL2Output(_l2OutputIndex).outputRoot matches
        L2Output memory output = l2Oracle.getL2Output(_l2OutputIndex);

        // WD-04: No finalization period check!
        // BUG: Missing: require(block.timestamp >= output.timestamp + FINALIZATION_PERIOD_SECONDS)

        // WD-07: L2 timestamp validation missing
        // BUG: output.timestamp not validated against l1Timestamp

        // Compute output root from proof components
        bytes32 computedOutputRoot = keccak256(abi.encode(
            _outputRootProof.version,
            _outputRootProof.stateRoot,
            _outputRootProof.messagePasserStorageRoot,
            _outputRootProof.latestBlockhash
        ));

        // WD-03: unchecked output root — outputRoot == computedOutputRoot not verified!
        // BUG: Missing `require(output.outputRoot == computedOutputRoot)`

        // WD-02: encodePacked length extension attack
        // BUG: Uses abi.encodePacked instead of abi.encode — hash collision possible!
        bytes32 withdrawalHash = keccak256(abi.encodePacked(
            _tx.nonce,
            _tx.sender,
            _tx.target,
            _tx.value,
            _tx.gasLimit,
            _tx.data
        ));

        // WD-11: withdrawalHash should include unique ID (chain ID, portal address)
        // BUG: Missing chainid + address(this) in hash — cross-chain replay possible

        // WD-01: Merkle trie verification
        bytes memory storageKey = abi.encodePacked(withdrawalHash);
        bytes memory storageValue = hex"01";

        // WD-01: SecureMerkleTrie.verifyInclusionProof can be bypassed
        require(
            SecureMerkleTrie.verifyInclusionProof(
                storageKey,
                storageValue,
                _withdrawalProof,
                _outputRootProof.messagePasserStorageRoot
            ),
            "Invalid proof"
        );

        // WD-09: Proven withdrawal can be overwritten!
        // BUG: No check `require(provenWithdrawals[withdrawalHash].timestamp == 0)`
        // Allows re-proving with a different output root
        provenWithdrawals[withdrawalHash] = ProvenWithdrawal({
            outputRoot: computedOutputRoot,
            timestamp: uint128(block.timestamp),
            l2OutputIndex: uint128(_l2OutputIndex)
        });

        emit WithdrawalProven(withdrawalHash, _tx.sender, _tx.target);
    }

    /**
     * @dev Finalize a proven withdrawal
     *
     * WD-06:  Finalization timestamp bypass
     * WD-08:  Finalization can be skipped
     * WD-10:  Not properly marked as finalized
     * WD-12:  Proof reuse — same proof for multiple finalizations
     * WD-13:  Storage proof forgery
     * WD-14:  L2 block number not validated
     * WD-15:  Disputed game output accepted
     */
    function finalizeWithdrawalTransaction(
        WithdrawalTransaction memory _tx
    ) external {
        // WD-02: Same encodePacked vulnerability as in prove
        bytes32 withdrawalHash = keccak256(abi.encodePacked(
            _tx.nonce,
            _tx.sender,
            _tx.target,
            _tx.value,
            _tx.gasLimit,
            _tx.data
        ));

        ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[withdrawalHash];

        // WD-06: Finalization timestamp check — uses < instead of <=
        // BUG: Attacker can finalize exactly at timestamp boundary
        require(
            block.timestamp < provenWithdrawal.timestamp + PROOF_MATURITY_DELAY_SECONDS,
            "Not mature"
        );
        // BUG: ^ Wrong direction! Should be >= not <
        // WD-06: This actually PREVENTS finalization after maturity!

        // WD-10: Finalized check is present but...
        // BUG: Check happens but finalizedWithdrawals not set atomically
        require(!finalizedWithdrawals[withdrawalHash], "Already finalized");

        // WD-15: Should check if disputed game output has been resolved
        // BUG: No check against DisputeGameFactory for game status
        // Missing: require(disputeGame.status() == GameStatus.DEFENDER_WINS)

        // WD-14: L2 block number not validated against output
        // BUG: No check that _tx data corresponds to valid L2 block

        // WD-13: Storage proof could be forged — no re-verification at finalization
        // BUG: Proof verified once at prove time but state may have changed

        // WD-08: Finalization skip — mark finalized AFTER external call
        // Execute the withdrawal
        (bool success,) = _tx.target.call{value: _tx.value, gas: _tx.gasLimit}(_tx.data);

        // WD-10: finalizedWithdrawals set AFTER external call — CEI violation
        // WD-12: If !success, withdrawal not marked finalized → can retry with same proof
        if (success) {
            finalizedWithdrawals[withdrawalHash] = true;
        }
        // BUG: If !success, withdrawal can be re-finalized (proof reuse)

        emit WithdrawalFinalized(withdrawalHash, success);
    }

    // ================================================================
    //                     OUTPUT ROOT PROPOSALS
    // ================================================================

    /**
     * @dev Propose L2 output root
     *
     * WD-05: Unauthorized proposer — no authorization check
     * WD-07: L2 timestamp not validated
     * WD-14: L2 block number not validated
     */
    function proposeL2Output(
        bytes32 _outputRoot,
        uint256 _l2BlockNumber,
        bytes32 _l1Blockhash,
        uint256 _l1BlockNumber
    ) external {
        // WD-05: Proposer authorization missing!
        // BUG: No `require(msg.sender == proposer)` check
        // Anyone can propose an output root

        // WD-07: L2 timestamp validation missing
        // BUG: No check that _l2BlockNumber > last proposed block

        // WD-14: L2 block number validation missing
        // BUG: No check _l2BlockNumber corresponds to valid L2 state

        // L1 blockhash validation (weak)
        if (_l1Blockhash != bytes32(0)) {
            require(blockhash(_l1BlockNumber) == _l1Blockhash, "Bad L1 blockhash");
        }
        // BUG: If _l1Blockhash == 0, the check is completely skipped!

        l2Outputs.push(L2Output({
            outputRoot: _outputRoot,
            timestamp: uint128(block.timestamp),
            l2BlockNumber: uint128(_l2BlockNumber)
        }));

        emit OutputProposed(_outputRoot, _l2BlockNumber, l2Outputs.length - 1);
    }

    // ================================================================
    //                   CROSS-DOMAIN MESSAGING
    // ================================================================

    /**
     * @dev Send cross-domain message (L2 → L1 or L1 → L2)
     *
     * MSG-03: Hash missing nonce — replay possible
     * MSG-06: Gas limit not properly validated
     * MSG-09: Version mismatch in encoding
     * MSG-10: Versioned encoding missing
     */
    function sendMessage(
        address _target,
        bytes calldata _message,
        uint32 _minGasLimit
    ) external payable {
        // MSG-06: Gas limit not validated against MIN_GAS_LIMIT
        // BUG: _minGasLimit can be 0 — message will fail on relay
        // Missing: require(_minGasLimit >= MIN_GAS_LIMIT)

        // MSG-11: Target validation missing
        // BUG: _target can be address(0) or address(this) — self-call
        // Missing: require(_target != address(this))

        // MSG-03: hashCrossDomainMessage without nonce!
        // BUG: Nonce not included in message hash — allows replay
        bytes32 msgHash = keccak256(abi.encodePacked(
            msg.sender,
            _target,
            msg.value,
            _message
        ));
        // BUG: Missing msgNonce in hash → duplicate messages collide

        // MSG-09: Version not encoded in message
        // MSG-10: No versioned encoding (should use encodeCrossDomainMessage)
        // BUG: Missing MESSAGE_VERSION prefix in hash

        // Increment nonce (but nonce isn't in hash!)
        msgNonce++;

        // MSG-16: Withdrawal logging — messageHash should include nonce
        emit SentMessage(_target, msg.sender, _message, msgNonce, _minGasLimit);
        emit MessagePassed(msgNonce, msg.sender, _target, msg.value, _minGasLimit, _message, msgHash);
    }

    /**
     * @dev Relay a cross-domain message
     *
     * MSG-01: Cross-chain replay — no chain ID in hash
     * MSG-02: Sender not validated (xDomainMsgSender)
     * MSG-04: Nonce manipulation possible
     * MSG-05: Relayer context manipulation
     * MSG-07: Failed message re-execution
     * MSG-08: Successful message tracking bypass
     * MSG-12: Sender spoofing via xDomainMsgSender
     * MSG-13: Value mismatch between msg.value and original
     * MSG-14: Callback reentrancy
     * MSG-15: Message queue manipulation
     */
    function relayMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _minGasLimit,
        bytes calldata _message
    ) external payable {
        // MSG-01: No chain ID in message hash — cross-chain replay possible!
        bytes32 msgHash = hashCrossDomainMessage(_nonce, _sender, _target, _value, _minGasLimit, _message);

        // MSG-04: Nonce manipulation — _nonce parameter not verified against contract state
        // BUG: _nonce can be any value — not checked against msgNonce counter

        // MSG-08: successfulMessages check happens but...
        // BUG: Check uses wrong hash (without version prefix)
        require(!successfulMessages[msgHash], "Already relayed");

        // MSG-07: Failed message re-execution
        // BUG: failedMessages allows retry without rate limiting
        // An attacker can re-execute failed messages indefinitely

        // MSG-02 / MSG-12: xDomainMsgSender spoofing
        // BUG: xDomainMsgSender set before external call — can be read by target
        // BUG: _sender parameter is trusted without verification
        xDomainMsgSender = _sender;

        // MSG-13: Value mismatch — msg.value != _value not checked!
        // BUG: Missing `require(msg.value == _value)`
        // Attacker can relay with different ETH amount

        // MSG-05: Relayer context — msg.sender (relayer) can influence execution
        // BUG: No check that relayer is authorized

        // MSG-14: Callback reentrancy — no reentrancy guard!
        // BUG: _entered flag exists but NOT checked
        // Target contract can re-enter relayMessage
        (bool success,) = _target.call{value: _value, gas: _minGasLimit}(_message);

        // MSG-12: xDomainMsgSender NOT reset after call!
        // BUG: Should set xDomainMsgSender = address(0) but doesn't
        // Next call can read stale sender

        if (success) {
            // MSG-08: Mark as successful
            successfulMessages[msgHash] = true;
            emit RelayedMessage(msgHash);
        } else {
            // MSG-07: Mark as failed — allows re-execution
            failedMessages[msgHash] = true;
            emit FailedRelayedMessage(msgHash);
        }
    }

    /**
     * @dev Re-execute a failed message
     * MSG-07: Failed messages can be replayed without limit
     */
    function retryFailedMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _minGasLimit,
        bytes calldata _message
    ) external payable {
        bytes32 msgHash = hashCrossDomainMessage(_nonce, _sender, _target, _value, _minGasLimit, _message);

        // MSG-07: Only checks if message failed, no retry limit
        require(failedMessages[msgHash], "Not a failed message");
        // BUG: No retryCount check — infinite retries possible

        // MSG-15: Message queue manipulation — order not enforced
        // BUG: Messages can be retried in any order

        xDomainMsgSender = _sender;
        (bool success,) = _target.call{value: _value, gas: _minGasLimit}(_message);

        if (success) {
            successfulMessages[msgHash] = true;
            // BUG: failedMessages[msgHash] not cleared!
            emit RelayedMessage(msgHash);
        }
    }

    /**
     * @dev Get cross-domain message sender
     * MSG-02: xDomainMessageSender can return spoofed value
     */
    function xDomainMessageSender() external view returns (address) {
        // MSG-02: Returns whatever was last set, even if stale
        // BUG: No check that we're in a cross-domain call
        return xDomainMsgSender;
    }

    /**
     * @dev Hash a cross-domain message
     * MSG-03: hashCrossDomainMessage missing critical fields
     * MSG-09: Version mismatch
     * MSG-10: No versioned encoding
     */
    function hashCrossDomainMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _minGasLimit,
        bytes calldata _message
    ) public pure returns (bytes32) {
        // MSG-03: Hash missing nonce in some paths
        // MSG-09: MESSAGE_VERSION not included in hash
        // MSG-10: Not using versioned encoding (encodeVersionedNonce)
        // MSG-01: No chain ID — cross-chain replay possible!

        // BUG: Uses abi.encodePacked — length extension attack
        // BUG: Missing version prefix, missing chain ID
        return keccak256(abi.encodePacked(
            _nonce,
            _sender,
            _target,
            _value,
            _minGasLimit,
            _message
        ));
    }

    /**
     * @dev Encode cross-domain message (broken versioning)
     * MSG-09: Version mismatch
     * MSG-10: Versioned encoding incorrect
     */
    function encodeCrossDomainMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _gasLimit,
        bytes memory _data
    ) public pure returns (bytes memory) {
        // MSG-09: Version should be part of nonce encoding
        // MSG-10: Missing version prefix
        // BUG: No encodeVersionedNonce(_nonce, MESSAGE_VERSION) call
        return abi.encodeWithSignature(
            "relayMessage(uint256,address,address,uint256,uint256,bytes)",
            _nonce, _sender, _target, _value, _gasLimit, _data
        );
    }

    // ================================================================
    //                    MSG-11: TARGET VALIDATION
    // ================================================================

    /**
     * @dev Validate message target
     * MSG-11: Target validation missing — allows self-calls
     */
    function isValidTarget(address _target) external view returns (bool) {
        // BUG: Allows address(this) as target
        // BUG: Allows address(0) as target
        // Should block: portal, messenger, system contracts
        return _target != address(0);
        // Missing: _target != address(this)
        // Missing: _target != address(l2Oracle)
    }

    // ================================================================
    //                    MSG-15: MESSAGE QUEUE
    // ================================================================

    /// @dev Message queue for ordered execution
    bytes32[] public messageQueue;

    /**
     * @dev Enqueue a message for ordered execution
     * MSG-15: Message queue manipulation — no ordering enforcement
     */
    function enqueueMessage(bytes32 _msgHash) external {
        // MSG-15: BUG: Anyone can add messages to queue
        // BUG: No ordering enforcement
        // BUG: No deduplication check
        messageQueue.push(_msgHash);
    }

    /**
     * @dev Dequeue and process next message
     * MSG-15: Queue can be front-run or reordered
     */
    function processNextMessage() external {
        require(messageQueue.length > 0, "Empty queue");

        // MSG-15: BUG: Processes last element, not first (LIFO, not FIFO)
        bytes32 msgHash = messageQueue[messageQueue.length - 1];
        messageQueue.pop();

        // BUG: Processing order can be manipulated by enqueueing before target message
    }

    // ================================================================
    //                    MSG-16: WITHDRAWAL LOGGING
    // ================================================================

    /**
     * @dev Log withdrawal for L2ToL1MessagePasser
     * MSG-16: Withdrawal logging incomplete — missing fields
     */
    function initiateWithdrawal(address _target, uint256 _gasLimit, bytes calldata _data) external payable {
        // MSG-16: withdrawalHash should use all fields including nonce
        // BUG: Missing sender, value in hash calculation
        bytes32 withdrawalHash = keccak256(abi.encodePacked(
            _target,
            _gasLimit,
            _data
        ));
        // BUG: Missing: msg.sender, msg.value, msgNonce in hash

        msgNonce++;
        emit MessagePassed(msgNonce, msg.sender, _target, msg.value, _gasLimit, _data, withdrawalHash);
    }

    // ========== HELPERS ==========

    function getL2OutputCount() external view returns (uint256) {
        return l2Outputs.length;
    }

    function getProvenWithdrawal(bytes32 _hash) external view returns (ProvenWithdrawal memory) {
        return provenWithdrawals[_hash];
    }

    /// @dev Accept ETH for withdrawal processing
    receive() external payable {}
}
