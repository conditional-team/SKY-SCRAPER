// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AssemblyLowLevel
 * @dev Training Contract #36 - Assembly / Low-Level Advanced Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Unsafe Memcpy/Memclear (ASM-ADV-01)
 * 2. Opcode Misuse in Inline Assembly (ASM-ADV-02)
 * 3. Delegatecall Assembly Miscalc (ASM-ADV-03)
 * 4. Storage Collision via Assembly (ASM-ADV-04)
 * 5. Inline Assembly Recursion (ASM-ADV-05)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): ASM-ADV-01→05
 * - Engine 9 (bytecode-flow-anomaly): assembly control flow issues
 * - Engine 49 (taint-engine): taint through assembly operations
 */

contract AssemblyExploits {
    mapping(address => uint256) public balances;
    mapping(uint256 => bytes) public dataStore;
    address public admin;
    address public implementation;
    uint256 public callDepth;

    constructor() {
        admin = msg.sender;
    }

    // ========== VULN 1: Unsafe Memcpy (ASM-ADV-01) ==========

    // BUG #1: memory copy without bounds checking
    function unsafeMemcpy(bytes memory src, uint256 destOffset, uint256 length) external pure returns (bytes memory dest) {
        dest = new bytes(64); // fixed size buffer
        assembly {
            // VULN: length not checked against dest capacity
            // If length > 64, writes past allocated memory
            let srcPtr := add(src, 0x20)
            let destPtr := add(add(dest, 0x20), destOffset)
            // No bounds check: destOffset + length could exceed dest size
            for { let i := 0 } lt(i, length) { i := add(i, 0x20) } {
                mstore(add(destPtr, i), mload(add(srcPtr, i)))
            }
        }
    }

    // Unsafe memclear — clears memory without checking boundaries
    function unsafeMemclear(uint256 ptr, uint256 length) external pure {
        assembly {
            // VULN: clears arbitrary memory region
            // Could overwrite important memory like free memory pointer
            for { let i := 0 } lt(i, length) { i := add(i, 0x20) } {
                mstore(add(ptr, i), 0)
            }
        }
    }

    // ========== VULN 2: Opcode Misuse (ASM-ADV-02) ==========

    // BUG #2: wrong stack order in assembly
    function opcodeConfusion(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            // VULN: div(a,b) in Yul means a/b, but EVM div pops b first then a
            // Developer confusion between Yul semantics and raw opcode order
            result := div(b, a) // intended a/b but wrote b/a

            // Missing pop — value left on stack
            let temp := add(a, b)
            // VULN: temp computed but never used, some compilers leave on stack
        }
    }

    // Incorrect return data handling
    function rawCall(address target, bytes memory data) external returns (bytes memory) {
        assembly {
            let success := call(gas(), target, 0, add(data, 0x20), mload(data), 0, 0)
            // VULN: returndatasize() used without checking success
            // On failure, returndata might contain revert reason, not actual data
            let size := returndatasize()
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, size)
            // VULN: not updating free memory pointer
            // mstore(0x40, add(ptr, size)) — missing!
            return(ptr, size)
        }
    }

    // ========== VULN 3: Delegatecall Assembly Miscalc (ASM-ADV-03) ==========

    // BUG #3: incorrect input/output buffer calculation for delegatecall
    function delegateWithBadBuffers(address target, bytes memory data) external returns (bool) {
        bool success;
        assembly {
            // VULN: calldatasize() used instead of data length for delegatecall
            // calldatasize() includes the function selector + all params, not just `data`
            success := delegatecall(
                gas(),
                target,
                add(data, 0x20),
                calldatasize(), // WRONG: should be mload(data)
                0,
                0
            )
            // VULN: output not properly handled
            // returndatacopy destination overlaps with input
            returndatacopy(add(data, 0x20), 0, returndatasize())
        }
        return success;
    }

    // ========== VULN 4: Storage Collision via Assembly (ASM-ADV-04) ==========

    // BUG #4: sstore/sload with dynamically computed slot collides with Solidity slots
    function assemblyStorage(uint256 key, uint256 value) external {
        assembly {
            // VULN: manually computing slot that might collide with balances mapping
            // keccak256(key, slot) where slot matches Solidity's balances mapping slot
            let slot := add(key, 0) // slot 0 = balances mapping base
            sstore(slot, value) // overwrites balances[0] or admin (slot 1)
        }
    }

    function readAssemblyStorage(uint256 slot) external view returns (uint256 value) {
        assembly {
            value := sload(slot) // can read any storage slot
        }
    }

    // More dangerous: hash-based slot that accidentally equals a mapping slot
    function writeToComputedSlot(bytes32 key) external {
        assembly {
            // VULN: this hash might collide with Solidity's mapping storage
            let slot := keccak256(0, 32)
            mstore(0, key)
            let computedSlot := keccak256(0, 32)
            sstore(computedSlot, caller()) // might overwrite existing state
        }
    }

    // ========== VULN 5: Inline Assembly Recursion (ASM-ADV-05) ==========

    // BUG #5: recursive call in assembly without depth/gas check
    function assemblyRecurse(uint256 depth) external {
        callDepth = depth;
        assembly {
            let d := sload(callDepth.slot)
            if gt(d, 0) {
                // VULN: recursive CALL without gas limit or depth check
                // Can cause stack overflow or consume all gas
                mstore(0, 0x12345678) // some selector
                mstore(4, sub(d, 1))
                let success := call(
                    gas(), // forwards ALL gas
                    address(),
                    0,
                    0,
                    36,
                    0,
                    0
                )
                // VULN: no gas check — runs until out of gas
                // No maximum depth limit
            }
        }
    }
}
