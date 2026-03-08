// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VyperCompatBugs
 * @dev Training Contract #58 - Vyper/Solidity Interop & Historical Bug Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Reentrancy Lock Bypass (VYPER-REENTER-01)
 * 2. Raw Call Return Ignored (VYPER-RAWCALL-01)
 * 3. Slice Out-of-Bounds (VYPER-SLICE-01)
 * 4. Curve-style Pool Reentrancy (VYPER-CURVE-01)
 * 5. Storage Layout Mismatch (VYPER-STORAGE-01)
 * 6. Default Function Fallback (VYPER-DEFAULT-01)
 * 7. Compiler Version Mismatch (VYPER-COMPILER-01)
 * 8. Interface ABI Mismatch (VYPER-ABI-01)
 * 9. Overflow in Unchecked Block (VYPER-OVERFLOW-01)
 * 10. Non-Reentrant Modifier Gap (VYPER-MODIFIER-01)
 * 11. Empty Return Padding (VYPER-RETURN-01)
 * 12. Dynamic Array Length Corruption (VYPER-DYNARRAY-01)
 * 13. Self-Destruct Recovery (VYPER-SELFDESTRUCT-01)
 * 14. Create2 Front-Running (VYPER-CREATE2-01)
 * 15. Boolean Packing Collision (VYPER-BOOLPACK-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): VYPER-*, reentrancy, raw_call, overflow
 * - Engine 2 (deep-semantic): interop vulnerabilities, ABI mismatch
 * - Engine 5 (compiler-vulns): version-specific issues, storage layout
 * - Engine 20 (bytecode-flow): control flow anomalies from compilation
 */

interface IVyperPool {
    function exchange(uint256 i, uint256 j, uint256 dx, uint256 min_dy) external;
    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint) external;
    function remove_liquidity(uint256 burn_amount, uint256[3] calldata min_amounts) external;
    function get_virtual_price() external view returns (uint256);
}

interface IVyperToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract VyperCompatExploits {

    // ========== VULN 1: Reentrancy Lock Bypass (VYPER-REENTER-01) ==========

    bool private _locked;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // BUG #1: Vyper 0.2.x @nonreentrant had a bug where the lock variable
    // could be bypassed through cross-function reentrancy
    // This Solidity version simulates the same broken lock pattern
    modifier nonReentrant_broken() {
        require(!_locked, "locked");
        _locked = true;
        _;
        // VULN: lock is released BEFORE callback finishes in original Vyper bug
        _locked = false;
    }

    function withdraw(uint256 amount) external nonReentrant_broken {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        totalShares -= amount;
        // VULN: callback can re-enter through remove_liquidity path
        // because Vyper 0.2.x lock scope didn't cover cross-function calls
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // ========== VULN 2: Raw Call Return Ignored (VYPER-RAWCALL-01) ==========

    // BUG #2: simulating Vyper's raw_call() where return value is ignored
    function executeVyperRawCall(address target, bytes calldata data) external {
        // VULN: raw_call in Vyper returns bytes but many contracts
        // don't check if the call succeeded
        target.call(data);
        // No success check, no return parse
    }

    // ========== VULN 3: Slice Out-of-Bounds (VYPER-SLICE-01) ==========

    // BUG #3: Vyper's slice() could read past buffer boundaries
    function unsafeSlice(bytes memory data, uint256 start, uint256 length) 
        external pure returns (bytes memory result) 
    {
        // VULN: no bounds check on start + length <= data.length
        // mirrors Vyper 0.3.1 CVE where slice could OOB read
        result = new bytes(length);
        assembly {
            let src := add(add(data, 0x20), start)
            let dst := add(result, 0x20)
            // Copies bytes even if start + length > data.length
            for { let i := 0 } lt(i, length) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    // ========== VULN 4: Curve-style Pool Reentrancy (VYPER-CURVE-01) ==========

    IVyperPool public curvePool;
    mapping(address => uint256) public lpBalances;

    // BUG #4: The July 2023 Curve exploit—reentrancy through ETH callback
    // in remove_liquidity on Vyper pools with @nonreentrant bug
    function removeLiquidityFromCurve(uint256 amount) external {
        require(lpBalances[msg.sender] >= amount, "insufficient");
        lpBalances[msg.sender] -= amount;
        
        // VULN: Vyper pool uses broken @nonreentrant, ETH transfer during
        // remove_liquidity allows reentering add_liquidity
        uint256[3] memory minAmounts;
        curvePool.remove_liquidity(amount, minAmounts);
        // State already updated but attacker re-entered during callback
    }

    // ========== VULN 5: Storage Layout Mismatch (VYPER-STORAGE-01) ==========

    // BUG #5: Vyper and Solidity use different storage layouts for mappings
    // Proxy pointing at both can corrupt state
    
    // Solidity: keccak256(key . slot) for mappings
    // Vyper: keccak256(slot . key) historically (reversed)
    
    uint256 public slot0_collides; // May collide with Vyper implementation vars
    mapping(address => uint256) public balances; // slot 1 in Solidity
    address public admin; // slot 2

    function writeToSlot(uint256 slot, bytes32 value) external {
        require(msg.sender == admin, "not admin");
        // VULN: direct sstore can corrupt Vyper implementation's storage
        assembly {
            sstore(slot, value)
        }
    }

    // ========== VULN 6: Default Function Fallback (VYPER-DEFAULT-01) ==========

    // BUG #6: Vyper's __default__() function has different behavior than Solidity's fallback
    // Can execute code on plain ETH transfers that Solidity proxies don't expect

    mapping(address => uint256) public depositedETH;

    fallback() external payable {
        // VULN: if this is a proxy reading from a Vyper impl,
        // the __default__ in Vyper may have side effects
        // that Solidity callers don't anticipate
        depositedETH[msg.sender] += msg.value;
    }

    // ========== VULN 7: Compiler Version Mismatch (VYPER-COMPILER-01) ==========

    // BUG #7: mixed Vyper compiler versions in same project
    // 0.2.x, 0.3.x, 0.4.x have different codegen, ABIs, optimizations
    uint256 public constant VYPER_COMPATIBILITY = 3;

    function callVyperContract(address target, bytes4 selector, uint256 arg) 
        external returns (bytes memory) 
    {
        // VULN: Vyper 0.2.x encodes return values differently than 0.3.x
        // calling a 0.2.x contract with 0.3.x ABI expectations corrupts data
        (bool ok, bytes memory ret) = target.call(abi.encodeWithSelector(selector, arg));
        require(ok, "call failed");
        return ret; // May be misinterpreted if Vyper version != expected
    }

    // ========== VULN 8: Interface ABI Mismatch (VYPER-ABI-01) ==========

    // BUG #8: Vyper functions returning multiple values encode differently
    // in older versions
    function decodeVyperReturn(bytes memory data) external pure returns (uint256 a, uint256 b) {
        // VULN: Vyper 0.2.x may pad return values differently
        // straight abi.decode may read garbage
        (a, b) = abi.decode(data, (uint256, uint256));
    }

    // ========== VULN 9: Overflow in Unchecked Block (VYPER-OVERFLOW-01) ==========

    // BUG #9: Vyper pre-0.3.4 didn't have overflow checks on certain ops
    // Solidity interop assumes overflow-safe results
    function processVyperResult(uint256 vyperOutput, uint256 multiplier) 
        external pure returns (uint256) 
    {
        // VULN: vyperOutput may have overflowed in the Vyper contract
        // this contract trusts it as accurate
        unchecked {
            return vyperOutput * multiplier; // double overflow risk
        }
    }

    // ========== VULN 10: Non-Reentrant Modifier Gap (VYPER-MODIFIER-01) ==========

    // BUG #10: Vyper's @nonreentrant("lock") only protects functions with same key
    // functions with different keys or no key can still be entered
    
    bool private _lockA;
    bool private _lockB;

    modifier lockGroupA() {
        require(!_lockA);
        _lockA = true;
        _;
        _lockA = false;
    }

    modifier lockGroupB() {
        require(!_lockB);
        _lockB = true;
        _;
        _lockB = false;
    }

    // VULN: functionA is locked under A, functionB under B
    // reentrance from A → B is possible
    function functionA() external lockGroupA {
        (bool ok, ) = msg.sender.call("");
        require(ok);
    }

    function functionB() external lockGroupB {
        // VULN: callable during functionA's callback
        shares[msg.sender] += 1000;
    }

    // ========== VULN 11: Empty Return Padding (VYPER-RETURN-01) ==========

    // BUG #11: Vyper contracts may return empty bytes for void functions
    // Solidity expects 32-byte padded return for bool
    function safeTransferFromVyper(address vyperToken, address to, uint256 amt) external {
        // VULN: if Vyper contract returns nothing for transfer(),
        // Solidity sees 0 bytes → success check may fail or succeed incorrectly
        (bool ok, bytes memory ret) = vyperToken.call(
            abi.encodeWithSelector(IVyperToken.transfer.selector, to, amt)
        );
        // Some tokens: ret.length == 0 means success (Vyper pattern)
        // Others: ret.length == 32 and must be true
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "transfer failed");
    }

    // ========== VULN 12: Dynamic Array Length Corruption (VYPER-DYNARRAY-01) ==========

    // BUG #12: Vyper DynArray had length corruption bug in 0.3.x
    uint256[] public dynamicArray;

    function pushUnsafe(uint256 value) external {
        dynamicArray.push(value);
        // VULN: if Vyper impl uses DynArray and length gets corrupted,
        // Solidity reading from same storage slot gets wrong length
        assembly {
            // Simulate corrupt length read
            let slot := dynamicArray.slot
            let len := sload(slot)
            // No validation that len matches actual contents
        }
    }

    // ========== VULN 13: Self-Destruct Recovery (VYPER-SELFDESTRUCT-01) ==========

    // BUG #13: Vyper's selfdestruct was accessible in older versions
    function emergencyDestruct() external {
        require(msg.sender == admin, "not admin");
        // VULN: selfdestruct deprecated in EIP-6780, but Vyper contracts
        // compiled pre-Dencun still include it. After Dencun, selfdestruct
        // in a created-same-tx contract still works → unexpected behavior
        selfdestruct(payable(admin));
    }

    // ========== VULN 14: Create2 Front-Running (VYPER-CREATE2-01) ==========

    // BUG #14: Create2 allows redeploying at same address after selfdestruct
    // Vyper factory can be front-run to deploy malicious version
    function deployVyperContract(bytes memory bytecode, bytes32 salt) 
        external returns (address deployed) 
    {
        // VULN: attacker front-runs with same salt, different bytecode
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(deployed) { revert(0, 0) }
        }
    }

    // ========== VULN 15: Boolean Packing Collision (VYPER-BOOLPACK-01) ==========

    // BUG #15: Vyper packs booleans into single storage slot differently than Solidity
    // Cross-contract proxy can corrupt packed booleans
    struct PackedConfig {
        bool paused;
        bool deprecated;
        bool emergencyMode;
        uint248 version;
    }

    PackedConfig public config;

    function setFlag(uint8 flagIndex, bool value) external {
        require(msg.sender == admin, "not admin");
        // VULN: manual bit manipulation doesn't account for Vyper's packing order
        assembly {
            let slot := config.slot
            let flags := sload(slot)
            let mask := shl(flagIndex, 1)
            switch value
            case 1 { flags := or(flags, mask) }
            default { flags := and(flags, not(mask)) }
            sstore(slot, flags)
        }
    }

    // ========== Setup ==========

    function setPool(address pool) external {
        require(msg.sender == admin);
        curvePool = IVyperPool(pool);
    }

    receive() external payable {
        depositedETH[msg.sender] += msg.value;
    }
}
