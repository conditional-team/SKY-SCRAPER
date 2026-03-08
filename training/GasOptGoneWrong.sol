// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title GasOptGoneWrong
 * @dev Training Contract #55 - Dangerous Gas Optimizations & Assembly Bugs
 *
 * VULNERABILITY CATEGORIES:
 * 1. Unchecked Overflow in Gas-Opt Loop (GASOPT-UNCHECKED-01)
 * 2. Bitshift Error in Encoding (GASOPT-BITSHIFT-01)
 * 3. Assembly Returndata Corruption (GASOPT-RETDATA-01)
 * 4. EIP-150 1/64 Gas Rule Exploit (GASOPT-EIP150-01)
 * 5. Dirty Memory Pointer (GASOPT-DIRTYMEM-01)
 * 6. Calldata vs Memory Confusion (GASOPT-CALLDATA-01)
 * 7. Packed Storage Overflow (GASOPT-PACKED-01)
 * 8. Free Memory Pointer Override (GASOPT-FMP-01)
 * 9. Yul Optimizer Bug (GASOPT-YULOPT-01)
 * 10. Missing Zero-Check in Assembly (GASOPT-ZEROCHECK-01)
 * 11. Transient Storage Misuse (GASOPT-TSTORE-01)
 * 12. MCOPY Memory Overlap (GASOPT-MCOPY-01)
 * 13. PUSH0 Compatibility Break (GASOPT-PUSH0-01)
 * 14. Short-Circuit Eval Gas Grief (GASOPT-SHORTCIRC-01)
 * 15. Custom Error Gas Bypass (GASOPT-CUSTOMERR-01)
 * 16. Inline Assembly Shadowing (GASOPT-SHADOW-01)
 * 17. Raw Call Return Check Skip (GASOPT-RAWCALL-01)
 * 18. Immutable vs Constant Confusion (GASOPT-IMMUT-01)
 * 19. Array Length Cache Stale (GASOPT-ARRLEN-01)
 * 20. ABIEncode Padding Attack (GASOPT-ABIPAD-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): GASOPT-*, unchecked, assembly, overflow
 * - Engine 2 (deep-semantic): arithmetic safety, memory management
 * - Engine 20 (bytecode-flow): CFG anomalies, dead code
 * - Engine 7 (compiler-vulns): optimizer bugs, version-specific
 */

contract GasOptGoneWrong {
    // Packed storage
    struct PackedUser {
        uint128 balance;
        uint64 lastAction;
        uint32 nonce;
        bool active;
        // 1 bit remaining in slot
    }

    mapping(address => PackedUser) public users;
    mapping(address => uint256) public balances;
    mapping(uint256 => address) public lookupTable;
    uint256 public totalSupply;
    address public owner;
    
    // Immutable vs constant
    address public immutable deployer;
    uint256 public constant MAX_SUPPLY = 1_000_000e18;

    constructor() {
        owner = msg.sender;
        deployer = msg.sender;
    }

    // ========== VULN 1: Unchecked Overflow in Gas-Opt Loop (GASOPT-UNCHECKED-01) ==========

    // BUG #1: unchecked block saves gas on ++i but allows overflow in sum
    function sumBalances(address[] calldata addrs) external view returns (uint256 total) {
        unchecked {
            for (uint256 i = 0; i < addrs.length; ++i) {
                // VULN: total can overflow silently in unchecked block
                // if many large balances, wraps around to small number
                total += balances[addrs[i]];
            }
        }
    }

    // ========== VULN 2: Bitshift Error in Encoding (GASOPT-BITSHIFT-01) ==========

    // BUG #2: packing multiple values with bit operations
    function packData(uint128 amount, uint64 timestamp, uint32 nonce) external pure returns (uint256) {
        // VULN: wrong shift amounts cause data overlap
        // nonce overlaps with timestamp bits
        return uint256(amount) << 128 | uint256(timestamp) << 32 | uint256(nonce);
        // Should be: amount << 96 | timestamp << 32 | nonce
        // Current: amount in bits 128-255, timestamp in bits 32-95, nonce in bits 0-31
        // But amount is 128 bits starting at 128 = bits 128-255 ✓
        // timestamp is 64 bits starting at 32 = bits 32-95 ✓
        // nonce is 32 bits at 0-31 ✓
        // ACTUALLY broken: amount << 128 only works if amount < 2^128
        // but uint128 cast already ensures this... the REAL bug is unpacking wrong
    }

    function unpackAmount(uint256 packed) external pure returns (uint128) {
        // VULN: shift by 96 instead of 128—reads garbage
        return uint128(packed >> 96); // wrong! should be >> 128
    }

    // ========== VULN 3: Assembly Returndata Corruption (GASOPT-RETDATA-01) ==========

    // BUG #3: assembly reads returndata buffer from previous call
    function safeTransfer(address token, address to, uint256 amount) external {
        assembly {
            let ptr := mload(0x40) // free memory pointer
            mstore(ptr, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 4), to)
            mstore(add(ptr, 36), amount)
            
            let success := call(gas(), token, 0, ptr, 68, 0, 32)
            
            // VULN: checks returndatasize but uses stale returndata from previous call
            // if token returns empty (like USDT), returndatasize == 0
            // but memory at 0x00 may contain old returndata = "true"
            if iszero(success) {
                revert(0, returndatasize())
            }
            // Missing: check that returndatasize() is 0 or returns true
        }
    }

    // ========== VULN 4: EIP-150 1/64 Gas Rule Exploit (GASOPT-EIP150-01) ==========

    // BUG #4: external call gets 63/64 of remaining gas
    // if called with precisely calculated gas, internal operations after call OOG
    function withdrawWithCallback(address user, uint256 amount) external {
        require(balances[user] >= amount, "insufficient");
        
        // External call gets 63/64 of gas
        (bool ok, ) = user.call{value: amount}("");
        // VULN: only 1/64 gas remains for state updates below
        // if gas is precisely tuned, these writes silently fail
        // in a try/catch pattern, the catch might not have enough gas either
        
        balances[user] -= amount; // may OOG here
        totalSupply -= amount;    // state inconsistent
    }

    // ========== VULN 5: Dirty Memory Pointer (GASOPT-DIRTYMEM-01) ==========

    // BUG #5: assembly doesn't clean upper bits of memory reads
    function getSelector(bytes calldata data) external pure returns (bytes4) {
        bytes4 selector;
        assembly {
            // VULN: calldataload reads 32 bytes, but we only want 4
            // upper 28 bytes could be dirty if memory was previously used
            selector := calldataload(data.offset)
            // Should mask: selector := and(calldataload(data.offset), 0xFFFFFFFF00000000000000000000000000000000000000000000000000000000)
        }
        return selector;
    }

    // ========== VULN 6: Calldata vs Memory Confusion (GASOPT-CALLDATA-01) ==========

    // BUG #6: function expects calldata but receives memory-allocated data
    function processItems(uint256[] calldata items) external returns (uint256) {
        // Efficient: reads directly from calldata
        uint256 result;
        for (uint256 i = 0; i < items.length; i++) {
            result += items[i];
        }
        
        // VULN: internal call re-encodes calldata items into memory
        // if _internalProcess modifies the array, original calldata is unaffected
        // but developer expects modifications to propagate
        return _internalProcess(items);
    }

    function _internalProcess(uint256[] calldata items) internal returns (uint256) {
        // Can't modify calldata—any gas optimization assuming modification is wrong
        uint256 total;
        for (uint256 i = 0; i < items.length; i++) {
            total += items[i];
            // VULN: developer may think they can modify items[i] for gas saving
            // but calldata is immutable
        }
        balances[msg.sender] = total;
        return total;
    }

    // ========== VULN 7: Packed Storage Overflow (GASOPT-PACKED-01) ==========

    // BUG #7: packed struct fields overflow into adjacent fields
    function updateUser(address user, uint128 newBalance) external {
        PackedUser storage u = users[user];
        // VULN: if newBalance is close to uint128.max and we add, it overflows
        // into lastAction field in same storage slot
        unchecked {
            u.balance += newBalance; // overflow corrupts lastAction
        }
        u.nonce++;
    }

    // ========== VULN 8: Free Memory Pointer Override (GASOPT-FMP-01) ==========

    // BUG #8: assembly code incorrectly updates free memory pointer
    function efficientHash(bytes calldata data) external pure returns (bytes32) {
        bytes32 result;
        assembly {
            let ptr := mload(0x40) // current free memory pointer
            calldatacopy(ptr, data.offset, data.length)
            result := keccak256(ptr, data.length)
            // VULN: free memory pointer NOT updated
            // next Solidity memory allocation overwrites hash input
            // mstore(0x40, add(ptr, data.length)) // MISSING!
        }
        return result;
    }

    // ========== VULN 9: Yul Optimizer Bug (GASOPT-YULOPT-01) ==========

    // BUG #9: specific pattern triggers Yul optimizer bug in older compilers
    function optimizerVictim(uint256 x) external pure returns (uint256) {
        uint256 result;
        assembly {
            // VULN: under certain optimizer settings, this sequence gets reordered
            // incorrectly, producing wrong result
            result := add(mul(x, 2), 1)
            // Optimizer may fold this differently based on context
            // Known issue in solc 0.8.13-0.8.17 with Yul optimizer
            if gt(result, 1000) {
                result := sub(result, 1000)
            }
            // Optimizer may eliminate the branch incorrectly
        }
        return result;
    }

    // ========== VULN 10: Missing Zero-Check in Assembly (GASOPT-ZEROCHECK-01) ==========

    // BUG #10: assembly division without zero check
    function efficientDiv(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 result;
        assembly {
            // VULN: division by zero in assembly doesn't revert—returns 0
            // Solidity normally checks, but assembly skips it
            result := div(a, b) // if b == 0, returns 0 silently
        }
        return result;
    }

    // ========== VULN 11: Transient Storage Misuse (GASOPT-TSTORE-01) ==========

    // BUG #11: transient storage used for critical state
    // survives within tx but lost after tx—race condition
    function setTransientLock() external {
        assembly {
            tstore(0, 1) // set lock
        }
    }

    function checkTransientLock() external view returns (bool) {
        bool isLocked;
        assembly {
            isLocked := tload(0)
        }
        // VULN: if checked in different tx, lock is gone
        // AND: different contracts reading same slot = collision
        return isLocked;
    }

    // ========== VULN 12: MCOPY Memory Overlap (GASOPT-MCOPY-01) ==========

    // BUG #12: mcopy with overlapping source and destination
    function shiftArray(uint256[] memory arr, uint256 offset) internal pure {
        assembly {
            let len := mload(arr)
            let srcPtr := add(arr, 32)
            let dstPtr := add(srcPtr, mul(offset, 32))
            // VULN: if offset is small, src and dst overlap
            // mcopy behavior with overlap is undefined in some contexts
            mcopy(dstPtr, srcPtr, mul(len, 32))
        }
    }

    // ========== VULN 13: PUSH0 Compatibility Break (GASOPT-PUSH0-01) ==========

    // BUG #13: contract compiled with Shanghai EVM features
    // but deployed on chain that doesn't support PUSH0
    function push0Dependent() external pure returns (uint256) {
        // VULN: compiler uses PUSH0 for zero-pushes
        // on chains without Shanghai upgrade, this reverts as invalid opcode
        return 0; // compiler emits PUSH0 instead of PUSH1 0x00
    }

    // ========== VULN 14: Short-Circuit Eval Gas Grief (GASOPT-SHORTCIRC-01) ==========

    // BUG #14: ordering of conditions in require affects gas on failure
    function conditionalTransfer(address to, uint256 amount) external {
        // VULN: expensive oracle check first, cheap balance check second
        // attacker sends tx with bad balance, wastes gas on oracle check
        require(
            _getOraclePrice() > 100e18 && // expensive: external call
            balances[msg.sender] >= amount, // cheap: storage read
            "failed"
        );
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // ========== VULN 15: Custom Error Gas Bypass (GASOPT-CUSTOMERR-01) ==========

    error InsufficientBalance(uint256 available, uint256 required);

    // BUG #15: custom error revert data can be truncated by gas limit
    function strictWithdraw(uint256 amount) external {
        if (balances[msg.sender] < amount) {
            // VULN: if gas is precisely limited, revert data is truncated
            // caller can't decode the error, doesn't know it's insufficient balance
            revert InsufficientBalance(balances[msg.sender], amount);
        }
        balances[msg.sender] -= amount;
    }

    // ========== VULN 16: Inline Assembly Shadowing (GASOPT-SHADOW-01) ==========

    // BUG #16: assembly variable shadows Solidity variable
    function shadowingBug(uint256 value) external pure returns (uint256) {
        uint256 result = value * 2;
        assembly {
            // VULN: 'result' in assembly refers to stack variable
            // but Solidity's result is at a different memory location
            let result := add(value, 1) // shadows outer 'result'
            mstore(0x00, result)        // stores wrong value
        }
        // Solidity's result unchanged, returns value * 2, not value + 1
        return result;
    }

    // ========== VULN 17: Raw Call Return Check Skip (GASOPT-RAWCALL-01) ==========

    // BUG #17: low-level call return not checked for gas efficiency
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // VULN: return value ignored for gas saving
            // failed transfers silently skipped
            recipients[i].call{value: amount}("");
            // If any transfer fails (e.g., contract recipient runs out of gas),
            // the sender still loses the ETH from their balance
        }
        balances[msg.sender] -= amount * recipients.length;
    }

    // ========== VULN 18: Immutable vs Constant Confusion (GASOPT-IMMUT-01) ==========

    // BUG #18: deployer is immutable (code-embedded), but owner is storage
    // admin checks use inconsistent comparison
    function adminAction() external {
        // VULN: checks deployer (immutable, can't be changed)
        // but should check owner (storage, transferable)
        // if ownership is transferred, old deployer retains admin rights
        require(msg.sender == deployer, "not admin");
        // ... admin logic
    }

    // ========== VULN 19: Array Length Cache Stale (GASOPT-ARRLEN-01) ==========

    uint256[] public dynamicArray;

    // BUG #19: caching array length for gas optimization, but array changes during loop
    function processAndPrune() external {
        uint256 len = dynamicArray.length; // cached
        for (uint256 i = 0; i < len; i++) {
            if (dynamicArray[i] > 100) {
                // VULN: modifying array length during iteration with cached length
                dynamicArray[i] = dynamicArray[dynamicArray.length - 1];
                dynamicArray.pop(); // length decreases, but len is stale
                // When i reaches old length, out-of-bounds access
            }
        }
    }

    // ========== VULN 20: ABIEncode Padding Attack (GASOPT-ABIPAD-01) ==========

    // BUG #20: abi.encodePacked with dynamic types causes collision
    function hashCollision(string calldata a, string calldata b) external pure returns (bytes32) {
        // VULN: abi.encodePacked("ab", "c") == abi.encodePacked("a", "bc")
        // used as mapping key → two different inputs map to same key
        return keccak256(abi.encodePacked(a, b));
        // Should use abi.encode(a, b) to include length prefixes
    }

    // ========== Helpers ==========

    function _getOraclePrice() internal pure returns (uint256) {
        return 200e18; // stub
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function pushArray(uint256 val) external {
        dynamicArray.push(val);
    }

    receive() external payable {}
}
