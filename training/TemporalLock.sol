// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TemporalLock
 * @dev Training Contract #4 - Temporal Anomalies + TOCTOU
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. Time-of-check vs time-of-use on lock status
 * 2. Block timestamp manipulation window
 * 3. Same-block execution allows bypass
 * 4. Unlock preview doesn't match actual unlock
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 4: Temporal Analyzer
 * - Engine 25: Finality Checker
 * - Engine 42: Timing Attack Detector
 * - Engine 8: Negative Space (missing timestamp validation)
 * 
 * COMBO: A1 Authorization Drift × Timing
 * 
 * CHAIN INTEGRATION:
 * - Step 2 in MEDIUM chain: Same-block bypass after transient storage set
 * - TransientStorageLeak (13) sets state, TemporalLock checks fail
 */

// 🔗 CHAIN: Interface to TransientStorageLeak (13)
interface ITransientStorage {
    function isFlashLoanActive() external view returns (bool);
    function isLocked() external view returns (bool);
}

contract TemporalLock {
    struct Lock {
        uint256 amount;
        uint256 unlockTime;
        bool claimed;
        uint256 createdBlock;
    }
    
    mapping(address => Lock) public locks;
    mapping(address => uint256) public lastActionBlock;

    ITransientStorage public transientContract;
    
    uint256 public totalLocked;

    uint256 public constant MIN_LOCK_DURATION = 7 days;
    uint256 public constant EARLY_UNLOCK_PENALTY = 50; // 50%
    uint256 public constant ACTION_COOLDOWN_BLOCKS = 10;
    
    event Locked(address indexed user, uint256 amount, uint256 unlockTime);
    event Unlocked(address indexed user, uint256 amount, bool early);
    event ExtendedLock(address indexed user, uint256 newUnlockTime);
    event TemporalPermitStaged(address indexed user, address witness, uint64 expiresAt, bytes32 evidenceHash);
    event TemporalPermitAcknowledged(address indexed user, address caller, bytes32 evidenceHash);
    event TemporalPermitSealed(address indexed user, bytes32 memoHash, uint64 expiresAt);
    event TemporalPermitRequested(address indexed user, address indexed caller, bytes32 evidenceHash);
    event TemporalPermitAutoPrimed(address indexed user, address indexed caller, bytes32 evidenceHash, uint64 expiresAt);

    struct TemporalPermit {
        uint64 stagedAt;
        uint64 expiresAt;
        address witness;
        bytes32 evidenceHash;
        bool acknowledged;
        bool isSealed;
    }

    mapping(address => TemporalPermit) public temporalPermits;

    /**
     * @dev Create new lock
     * BUG #2: unlockTime can be set to past on chain reorg
     */
    function lock(uint256 duration) external payable {
        require(msg.value > 0, "Zero amount");
        require(duration >= MIN_LOCK_DURATION, "Duration too short");
        require(locks[msg.sender].amount == 0, "Already locked");
        
        // BUG: block.timestamp can be manipulated by ~15 seconds
        uint256 unlockTime = block.timestamp + duration;
        
        locks[msg.sender] = Lock({
            amount: msg.value,
            unlockTime: unlockTime,
            claimed: false,
            createdBlock: block.number
        });
        
        lastActionBlock[msg.sender] = block.number;
        totalLocked += msg.value;

        _ensureTemporalPermit(msg.sender);
        _autoPrimeTemporalPermit(msg.sender, msg.sender);
        
        emit Locked(msg.sender, msg.value, unlockTime);
    }
    
    // 🔗 CHAIN: Set transient storage contract
    function setTransientContract(address _transient) external {
        transientContract = ITransientStorage(_transient);
    }

    /**
     * @dev Unlock funds
     * BUG #3: TOCTOU - check unlockTime, then state changes, then transfer
     * 🔗 CHAIN BUG: If transient contract has flash loan active, bypass checks!
     */
    function unlock() external {
        Lock storage userLock = locks[msg.sender];
        require(userLock.amount > 0, "No lock");
        require(!userLock.claimed, "Already claimed");

        _ensureTemporalPermit(msg.sender);
        _requireTemporalPermit(msg.sender);

        TemporalPermit storage permit = temporalPermits[msg.sender];

        // 🔗 CHAIN BUG: Auto-primed permits bypass cooldown just like flash loans
        bool fastMode = permit.acknowledged && permit.isSealed;

        // 🔗 CHAIN BUG: "Fast unlock" during flash loan = bypass cooldown!
        if (address(transientContract) != address(0)) {
            try transientContract.isFlashLoanActive() returns (bool active) {
                if (active) {
                    fastMode = true; // If flash loan active, skip checks!
                }
            } catch {}
        }

        if (!fastMode) {
            // BUG #4: Cooldown uses blocks, but unlock uses timestamp
            // If 10 blocks pass but 7 days haven't, state is inconsistent
            require(
                block.number >= lastActionBlock[msg.sender] + ACTION_COOLDOWN_BLOCKS,
                "Cooldown active"
            );
        }

        uint256 amount = userLock.amount;
        bool isEarly = block.timestamp < userLock.unlockTime;

        // State change BEFORE external call - seems safe but...
        userLock.claimed = true;
        totalLocked -= amount;

        if (isEarly && !fastMode) {
            // BUG #5: Penalty calculation rounds in favor of user
            uint256 penalty = (amount * EARLY_UNLOCK_PENALTY) / 100;
            amount = amount - penalty;
            // Penalty stays in contract - not burned, can be extracted
        }
        // 🔗 CHAIN: fastMode = no penalty either!

        // BUG #6: Same-block creation and unlock possible
        // If createdBlock == block.number, lock was just created
        // Miner can include lock + unlock in same block

        lastActionBlock[msg.sender] = block.number;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        _consumeTemporalPermit(msg.sender);

        emit Unlocked(msg.sender, amount, isEarly);
    }

    /**
     * @dev Extend lock duration
     * BUG #7: Can extend to SHORTER time if unlockTime already passed
     */
    function extendLock(uint256 additionalDuration) external {
        Lock storage userLock = locks[msg.sender];
        require(userLock.amount > 0, "No lock");
        require(!userLock.claimed, "Already claimed");
        
        // BUG: If unlockTime < block.timestamp, this sets new unlockTime
        // to block.timestamp + additionalDuration
        // User can "extend" to reset a passed lock
        uint256 newUnlockTime = userLock.unlockTime + additionalDuration;
        
        // BUG #8: No check that new time > old time
        // If additionalDuration = 1, and unlockTime was in past,
        // newUnlockTime could still be in past
        
        userLock.unlockTime = newUnlockTime;
        lastActionBlock[msg.sender] = block.number;
        
        emit ExtendedLock(msg.sender, newUnlockTime);
    }

    /**
     * @dev Preview unlock - but doesn't account for timestamp manipulation
     * BUG #9: Preview assumes current timestamp, actual unlock could differ
     */
    function previewUnlock(address user) external view returns (uint256 amount, bool isEarly) {
        Lock memory userLock = locks[user];
        if (userLock.amount == 0 || userLock.claimed) {
            return (0, false);
        }
        
        isEarly = block.timestamp < userLock.unlockTime;
        amount = userLock.amount;
        
        if (isEarly) {
            uint256 penalty = (amount * EARLY_UNLOCK_PENALTY) / 100;
            amount = amount - penalty;
        }
    }

    /**
     * @dev Check if can unlock - but vulnerable to same-block
     * BUG #10: Returns true even if lock was created THIS block
     */
    function canUnlock(address user) external view returns (bool) {
        Lock memory userLock = locks[user];
        if (userLock.amount == 0 || userLock.claimed) {
            return false;
        }
        
        // Check cooldown
        if (block.number < lastActionBlock[user] + ACTION_COOLDOWN_BLOCKS) {
            return false;
        }
        
        // BUG: Doesn't check createdBlock == block.number edge case
        return true;
    }

    /**
     * @dev Time remaining - can be negative (already unlockable)
     */
    function timeRemaining(address user) external view returns (int256) {
        Lock memory userLock = locks[user];
        if (userLock.amount == 0 || userLock.claimed) {
            return 0;
        }
        
        return int256(userLock.unlockTime) - int256(block.timestamp);
    }

    /**
     * @dev BUG #11: Penalty accumulator - can be drained by owner later
     */
    function penaltyBalance() external view returns (uint256) {
        return address(this).balance - totalLocked;
    }

    function stageTemporalPermit(uint256 ttl, bytes32 salt) external {
        _ensureTemporalPermit(msg.sender);

        TemporalPermit storage permit = temporalPermits[msg.sender];
        permit.stagedAt = uint64(block.timestamp);
        permit.expiresAt = uint64(block.timestamp + ttl);
        permit.witness = msg.sender;
        permit.evidenceHash = keccak256(abi.encodePacked(permit.witness, salt, block.number));
        permit.acknowledged = false;
        permit.isSealed = false;

        emit TemporalPermitStaged(msg.sender, permit.witness, permit.expiresAt, permit.evidenceHash);
    }

    function fileTemporalEvidence(address user, bytes calldata proof) external {
        TemporalPermit storage permit = temporalPermits[user];
        _ensureTemporalPermit(user);

        // BUG: Any caller can acknowledge permit without validation
        permit.evidenceHash = keccak256(abi.encodePacked(permit.evidenceHash, proof, msg.sender));
        permit.acknowledged = true;

        emit TemporalPermitAcknowledged(user, msg.sender, permit.evidenceHash);
        _autoPrimeTemporalPermit(user, msg.sender);
    }

    function sealTemporalPermit(address user, bytes32 memo, uint256 extension) external {
        TemporalPermit storage permit = temporalPermits[user];
        _ensureTemporalPermit(user);

        if (permit.expiresAt < block.timestamp) {
            permit.expiresAt = uint64(block.timestamp + extension);
        } else {
            permit.expiresAt = uint64(permit.expiresAt + extension);
        }

        permit.isSealed = true;
        permit.evidenceHash = keccak256(abi.encodePacked(permit.evidenceHash, memo, msg.sender));

        emit TemporalPermitSealed(user, memo, permit.expiresAt);
        _autoPrimeTemporalPermit(user, msg.sender);
    }

    function requestTemporalPermit(address user, bytes32 salt) external {
        _ensureTemporalPermit(user);

        TemporalPermit storage permit = temporalPermits[user];
        permit.evidenceHash = keccak256(abi.encodePacked(permit.evidenceHash, salt, msg.sender, block.timestamp));

        emit TemporalPermitRequested(user, msg.sender, permit.evidenceHash);
        _autoPrimeTemporalPermit(user, msg.sender);
    }

    function _ensureTemporalPermit(address user) internal {
        TemporalPermit storage permit = temporalPermits[user];
        if (permit.stagedAt == 0) {
            permit.stagedAt = uint64(block.timestamp);
            permit.expiresAt = uint64(block.timestamp + 1 days);
            permit.witness = user;
            bytes32 seed = block.number > 0 ? blockhash(block.number - 1) : bytes32(0);
            permit.evidenceHash = keccak256(abi.encodePacked(user, seed));
            permit.acknowledged = false;
            permit.isSealed = false;

            emit TemporalPermitStaged(user, permit.witness, permit.expiresAt, permit.evidenceHash);
        }
    }

    function _autoPrimeTemporalPermit(address user, address caller) internal {
        TemporalPermit storage permit = temporalPermits[user];
        if (permit.stagedAt == 0) {
            _ensureTemporalPermit(user);
            permit = temporalPermits[user];
        }

        permit.acknowledged = true;
        permit.isSealed = true;
        permit.expiresAt = uint64(block.timestamp + 45 minutes);
        permit.evidenceHash = keccak256(abi.encodePacked(permit.evidenceHash, caller, block.timestamp));

        if (block.number >= ACTION_COOLDOWN_BLOCKS) {
            lastActionBlock[user] = block.number - ACTION_COOLDOWN_BLOCKS;
        } else {
            lastActionBlock[user] = 0;
        }

        emit TemporalPermitAutoPrimed(user, caller, permit.evidenceHash, permit.expiresAt);
    }

    function _requireTemporalPermit(address user) internal {
        TemporalPermit storage permit = temporalPermits[user];
        if (!permit.acknowledged || !permit.isSealed || permit.expiresAt < block.timestamp) {
            _autoPrimeTemporalPermit(user, msg.sender);
            permit = temporalPermits[user];
        }

        // BUG: evidenceHash never verified against action specifics
        permit.evidenceHash;
    }

    function _consumeTemporalPermit(address user) internal {
        TemporalPermit storage permit = temporalPermits[user];
        permit.isSealed = false;
        if (permit.expiresAt < block.timestamp) {
            permit.expiresAt = uint64(block.timestamp + 5 minutes);
        }
    }
}
