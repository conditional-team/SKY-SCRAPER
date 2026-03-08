// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title StorageTimingLogic
 * @dev Training Contract #43 - Storage / Cross-Contract / Timing / Logic (20 vulns)
 *
 * VULNERABILITY CATEGORIES:
 * 1. Storage Slot Collision via Inheritance (STOR-ADV-01)
 * 2. Struct Packing Overflow (STOR-ADV-02)
 * 3. Dynamic Array Storage Overlap (STOR-ADV-03)
 * 4. Mapping Key Collision (STOR-ADV-04)
 * 5. ERC-7201 Namespace Violation (STOR-ADV-05)
 * 6. Cross-Contract View Dependency (XCON-ADV-01)
 * 7. Shared State Mutation (XCON-ADV-02)
 * 8. Callback State Desync (XCON-ADV-03)
 * 9. Library Delegatecall Corruption (XCON-ADV-04)
 * 10. Multi-Contract Invariant Break (XCON-ADV-05)
 * 11. Block Timestamp Manipulation (TIME-ADV-01)
 * 12. Block Number Dependency (TIME-ADV-02)
 * 13. Deadline Bypass (TIME-ADV-03)
 * 14. Epoch Transition Race (TIME-ADV-04)
 * 15. Cooldown Reset Exploit (TIME-ADV-05)
 * 16. Wrong Comparison Operator (LOGIC-ADV-01)
 * 17. Off-by-One in Loop (LOGIC-ADV-02)
 * 18. Incorrect Ternary (LOGIC-ADV-03)
 * 19. Missing Break in Switch-like Logic (LOGIC-ADV-04)
 * 20. Negation of Unsigned Int (LOGIC-ADV-05)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): STOR-ADV, XCON-ADV, TIME-ADV, LOGIC-ADV
 * - Engine 6 (storage-layout): storage collisions
 * - Engine 4 (temporal-analyzer): timing issues
 * - Engine 7 (deep-analyzer): logic bugs
 */

// ========== STORAGE EXPLOITS ==========

// BUG #1: STOR-ADV-01 — storage slot collision via inheritance
contract StorageBase {
    uint256 public adminSlot; // slot 0
    address public owner;     // slot 1
}

contract StorageChild is StorageBase {
    // VULN: expects slot 2, but if another parent is inserted,
    // slot numbers shift — balance overwrites owner
    uint256 public balance;   // slot 2 (fragile if inheritance changes)

    // BUG #2: STOR-ADV-02 — struct packing overflow
    struct PackedData {
        uint128 amount;
        uint64 timestamp;
        uint32 nonce;
        bool active; // packed in same slot
    }

    mapping(address => PackedData) public userData;

    function setData(address user, uint128 amount, uint64 ts, uint32 nonce) external {
        // VULN: if amount exceeds uint128.max, it overflows into timestamp field
        // Struct packing means adjacent fields share storage slot
        userData[user] = PackedData(amount, ts, nonce, true);
    }

    // BUG #3: STOR-ADV-03 — dynamic array overlaps mapping storage
    uint256[] public dynamicArray;
    mapping(uint256 => uint256) public dataMap;

    function pushToArray(uint256 val) external {
        dynamicArray.push(val);
        // VULN: dynamic array element storage at keccak256(slot) + index
        // Could collide with mapping storage at keccak256(key . slot)
    }

    // BUG #4: STOR-ADV-04 — mapping key collision with abi.encodePacked
    mapping(bytes32 => uint256) public genericMap;

    function setByKey(string calldata a, string calldata b) external {
        // VULN: abi.encodePacked("ab", "c") == abi.encodePacked("a", "bc")
        bytes32 key = keccak256(abi.encodePacked(a, b));
        genericMap[key] = 1;
    }

    // BUG #5: STOR-ADV-05 — ERC-7201 namespace collision
    bytes32 constant NAMESPACE_A = keccak256("my.storage.namespace");
    bytes32 constant NAMESPACE_B = keccak256("my.storage.namespace"); // same!

    function writeNamespaced(uint256 val) external {
        // VULN: two different logical storages using same namespace
        bytes32 ns = NAMESPACE_A;
        assembly {
            sstore(ns, val) // collides with NAMESPACE_B reads
        }
    }
}

// ========== CROSS-CONTRACT EXPLOITS ==========

contract ContractA {
    uint256 public sharedValue;
    address public contractB;

    // BUG #6: XCON-ADV-01 — view function depends on external state
    function getComputedValue() external view returns (uint256) {
        // VULN: view function calls external contract — result can change
        // between check and use in same transaction
        (bool ok, bytes memory data) = contractB.staticcall(
            abi.encodeWithSignature("getValue()")
        );
        require(ok);
        return abi.decode(data, (uint256)) + sharedValue;
    }

    // BUG #7: XCON-ADV-02 — shared state modified by both contracts
    function updateShared(uint256 newVal) external {
        // VULN: ContractB can also modify sharedValue via delegatecall
        // Race condition between two contracts modifying same state
        sharedValue = newVal;
    }

    // BUG #8: XCON-ADV-03 — callback causes state desync
    function processWithCallback(address target, uint256 amount) external {
        sharedValue += amount;
        // VULN: callback to target can re-enter and see intermediate state
        (bool ok,) = target.call(abi.encodeWithSignature("onProcess(uint256)", amount));
        require(ok);
        // sharedValue might have been modified during callback
    }
}

// BUG #9: XCON-ADV-04 — library delegatecall corrupts caller storage
library UnsafeLib {
    function unsafeWrite(uint256 slot, uint256 value) internal {
        // VULN: library writes to arbitrary storage slots in caller context
        assembly {
            sstore(slot, value)
        }
    }
}

contract LibUser {
    address public owner; // slot 0
    uint256 public balance; // slot 1

    function execute() external {
        // VULN: library writes slot 0, overwriting owner
        UnsafeLib.unsafeWrite(0, uint256(uint160(msg.sender)));
    }
}

// BUG #10: XCON-ADV-05 — multi-contract invariant: A.total == B.total
contract PoolA {
    uint256 public totalA;
    function deposit(uint256 amount) external {
        totalA += amount;
        // VULN: should also update PoolB.totalB but doesn't
        // Invariant totalA == totalB breaks
    }
}

contract PoolB {
    uint256 public totalB;
    function syncFrom(address poolA) external {
        // Called separately, creating window where invariant is broken
        (bool ok, bytes memory data) = poolA.staticcall(
            abi.encodeWithSignature("totalA()")
        );
        require(ok);
        totalB = abi.decode(data, (uint256));
    }
}

// ========== TIMING EXPLOITS ==========

contract TimingExploits {
    mapping(address => uint256) public lastAction;
    mapping(address => uint256) public cooldowns;
    uint256 public epochStart;
    uint256 public epochDuration = 1 days;
    uint256 public currentEpoch;
    mapping(uint256 => uint256) public epochRewards;
    mapping(address => uint256) public deadlines;

    // BUG #11: TIME-ADV-01 — block.timestamp manipulation (±15 sec)
    function timeLock(uint256 unlockTime) external payable {
        require(unlockTime > block.timestamp + 60, "too soon");
        // VULN: validator can adjust block.timestamp by ±15 seconds
        // 60-second lock can be bypassed to ~45 seconds
        lastAction[msg.sender] = unlockTime;
    }

    function unlock() external {
        require(block.timestamp >= lastAction[msg.sender], "locked");
        payable(msg.sender).transfer(1 ether);
    }

    // BUG #12: TIME-ADV-02 — block.number as time proxy
    function blockBasedLock() external view returns (bool) {
        // VULN: block time varies (12 sec on mainnet, 2 sec on L2)
        // Same block count = very different real time on different chains
        return block.number > 100000; // meaningless without chain context
    }

    // BUG #13: TIME-ADV-03 — deadline set but not enforced
    function setDeadline(uint256 deadline) external {
        deadlines[msg.sender] = deadline;
    }

    function executeAfterDeadline() external {
        // VULN: checks deadline but allows execution AT deadline
        // Should be strictly greater than
        require(block.timestamp >= deadlines[msg.sender], "too early");
        // Can execute at exact deadline time — off by one in time
    }

    // BUG #14: TIME-ADV-04 — epoch transition race
    function claimEpochReward() external {
        uint256 epoch = (block.timestamp - epochStart) / epochDuration;
        // VULN: claim at epoch boundary — reward allocated to old epoch
        // but user claims from new epoch, or claims from both
        if (epoch > currentEpoch) {
            currentEpoch = epoch;
        }
        uint256 reward = epochRewards[epoch];
        payable(msg.sender).transfer(reward);
    }

    // BUG #15: TIME-ADV-05 — cooldown reset by making any action
    function setCooldown(address user, uint256 duration) external {
        cooldowns[user] = block.timestamp + duration;
    }

    function actionWithCooldown() external {
        require(block.timestamp >= cooldowns[msg.sender], "cooling down");
        // VULN: any other action (deposit, etc.) resets lastAction
        // which is used as cooldown reference elsewhere
        lastAction[msg.sender] = block.timestamp;
    }
}

// ========== LOGIC EXPLOITS ==========

contract LogicExploits {
    mapping(address => uint256) public balances;
    address[] public whitelist;
    uint256 public threshold = 100;
    bool public paused;

    // BUG #16: LOGIC-ADV-01 — wrong comparison operator
    function isEligible(address user) external view returns (bool) {
        // VULN: should be >= but uses > — users with exactly threshold balance excluded
        return balances[user] > threshold; // should be >=
    }

    // BUG #17: LOGIC-ADV-02 — off-by-one in loop bound
    function processWhitelist() external {
        // VULN: <= instead of < — reads past array bounds
        // In Solidity 0.8+ this reverts, but in older versions UB
        for (uint i = 0; i <= whitelist.length; i++) {
            // Process whitelist[i] — last iteration reads garbage
        }
    }

    // BUG #18: LOGIC-ADV-03 — inverted ternary condition
    function getDiscount(uint256 amount) external view returns (uint256) {
        // VULN: condition is backwards — high spenders get NO discount
        // low spenders get big discount
        return amount > 1000
            ? amount * 100 / 100  // should be discounted but isn't
            : amount * 80 / 100;  // small buyer gets 20% discount instead
    }

    // BUG #19: LOGIC-ADV-04 — missing break in if-else chain
    function getRole(uint256 level) external pure returns (string memory) {
        // VULN: no else-if — all conditions evaluated, last one wins
        string memory role = "user";
        if (level >= 1) role = "member";
        if (level >= 5) role = "moderator";
        if (level >= 10) role = "admin";
        // Level 1 user becomes member, but level check continues
        // Not a bug per se in Solidity, but shows intent mismatch if early return expected
        return role;
    }

    // BUG #20: LOGIC-ADV-05 — negation on unsigned causes revert
    function negate(uint256 value) external pure returns (uint256) {
        // VULN: unary minus on uint causes underflow revert in 0.8+
        // In <0.8, wraps to huge number
        // Solidity 0.8+ will revert, but the logic intent is wrong
        return 0 - value; // should use int256 for negation
    }
}
