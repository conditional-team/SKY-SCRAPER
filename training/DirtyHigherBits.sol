// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DirtyHigherBits
 * @dev Training Contract #12 - ABI Encoding Edge Cases
 * 
 * MASTER LEVEL VULNERABILITY:
 * 1. Solidity cleans higher-order bits for addresses (160-bit)
 * 2. But raw calldata can have dirty bits in the upper 96 bits
 * 3. Some checks pass with dirty bits, hashes don't match
 * 4. Signature verification can be bypassed
 * 5. abi.encodePacked type confusion (uint128 x 2 == uint256 collision)
 * 6. Assembly calldataload bypasses Solidity's automatic cleaning
 * 7. Dirty bits survive delegatecall boundaries
 * 
 * REAL EXPLOIT: Multiple signature replay attacks
 * 
 * CHAIN INTEGRATION:
 * - Works with Contract 02 (AuthorityChain) for permission bypass
 * - Dirty bits in delegate address passes `==` but fails mapping lookup
 */

contract DirtyHigherBits {
    // Permission system
    mapping(address => bool) public isAdmin;
    mapping(bytes32 => bool) public usedSignatures;
    
    // Whitelist stored as bytes32 for "gas optimization"
    mapping(bytes32 => bool) public whitelistHashes;
    
    address public owner;
    uint256 public treasuryBalance;
    
    event AdminAdded(address indexed admin);
    event WhitelistAdded(bytes32 indexed hash);
    event Withdrawn(address indexed to, uint256 amount);
    
    constructor() {
        owner = msg.sender;
        isAdmin[msg.sender] = true;
        treasuryBalance = 0;
    }
    
    receive() external payable {
        treasuryBalance += msg.value;
    }
    
    /**
     * @dev Add admin by address
     * BUG: Stores cleaned address, but check might receive dirty
     */
    function addAdmin(address admin) external {
        require(isAdmin[msg.sender], "Not admin");
        isAdmin[admin] = true;
        emit AdminAdded(admin);
    }
    
    /**
     * @dev Add to whitelist using hash
     * BUG: Different hash if input has dirty bits
     */
    function addToWhitelist(address addr) external {
        require(isAdmin[msg.sender], "Not admin");
        bytes32 hash = keccak256(abi.encodePacked(addr));
        whitelistHashes[hash] = true;
        emit WhitelistAdded(hash);
    }
    
    /**
     * @dev Check whitelist - VULNERABLE
     * If called with dirty higher bits:
     * - `addr` gets cleaned for the require check
     * - But keccak256 hashes the FULL 32 bytes from calldata
     */
    function isWhitelisted(address addr) external view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(addr));
        return whitelistHashes[hash];
    }
    
    /**
     * @dev Withdraw with signature
     * BUG: Signature covers raw calldata, check uses cleaned address
     */
    function withdrawWithSig(
        address to,
        uint256 amount,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        // Build message hash from parameters
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n52",
            to,
            amount
        ));
        
        // Recover signer
        address signer = ecrecover(messageHash, v, r, s);
        require(isAdmin[signer], "Invalid signature");
        
        // Check signature not used
        // BUG: If 'to' had dirty bits, this hash is different!
        bytes32 sigHash = keccak256(abi.encodePacked(r, s, v, to, amount));
        require(!usedSignatures[sigHash], "Signature used");
        usedSignatures[sigHash] = true;
        
        // Transfer - uses cleaned address
        require(treasuryBalance >= amount, "Insufficient");
        treasuryBalance -= amount;
        payable(to).transfer(amount);
        
        emit Withdrawn(to, amount);
    }
    
    /**
     * @dev Execute arbitrary call with admin check
     * BUG: Admin check uses msg.sender (always clean)
     * But if called via delegatecall with dirty bits...
     */
    function executeAsAdmin(
        address target,
        bytes calldata data
    ) external returns (bytes memory) {
        require(isAdmin[msg.sender], "Not admin");
        
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        
        return result;
    }
    
    /**
     * @dev Low-level verification that exposes the bug
     * Compares raw calldata bytes vs cleaned address
     */
    function verifyAddressEncoding(address addr) external pure returns (
        bytes32 rawCalldataHash,
        bytes32 cleanedHash,
        bool matches
    ) {
        // This gets the raw 32 bytes from calldata (including dirty bits)
        bytes32 raw;
        assembly {
            // Load 32 bytes starting at calldata position 4 (after selector)
            raw := calldataload(4)
        }
        
        // This is the cleaned version
        bytes32 cleaned = bytes32(uint256(uint160(addr)));
        
        rawCalldataHash = keccak256(abi.encodePacked(raw));
        cleanedHash = keccak256(abi.encodePacked(cleaned));
        matches = (rawCalldataHash == cleanedHash);
    }
    
    /**
     * @dev Batch operation vulnerable to dirty bits
     * Array of addresses might have dirty bits in some elements
     */
    function batchWhitelist(address[] calldata addrs) external {
        require(isAdmin[msg.sender], "Not admin");
        
        for (uint i = 0; i < addrs.length; i++) {
            // BUG: Each address cleaned individually
            // But calldata has raw bytes
            bytes32 hash = keccak256(abi.encodePacked(addrs[i]));
            whitelistHashes[hash] = true;
        }
    }

    // ========== REAL DIRTY BITS VULNERABILITIES (Assembly) ==========
    
    /**
     * @dev Whitelist check using raw calldata - ACTUALLY EXPLOITABLE
     * BUG #5: calldataload reads FULL 32 bytes including dirty higher bits
     * Same address with different dirty bits -> different hash -> whitelist bypass
     *
     * Attack: Whitelisted 0x0000...ADDR (clean), query 0xDEAD...ADDR (dirty)
     * keccak256 differs -> returns false for a whitelisted address
     */
    function unsafeWhitelistCheck(address /* addr */) external view returns (bool) {
        bytes32 rawInput;
        assembly {
            // Load FULL 32 bytes at calldata position 4 (after selector)
            // If caller sends 0xDEADBEEF...0000<20-byte-addr>, raw includes dirty bits
            rawInput := calldataload(4)
        }
        // Hash includes dirty bits -> never matches stored clean hash
        bytes32 hash = keccak256(abi.encodePacked(rawInput));
        return whitelistHashes[hash];
    }
    
    /**
     * @dev Withdraw using raw calldata comparison - ACTUALLY EXPLOITABLE
     * BUG #6: Assembly eq() compares full 32 bytes
     * address(owner) stored clean != dirty-padded address(owner) from calldata
     *
     * Attack: Call with owner address + dirty higher bits -> eq() fails
     * OR: owner stored cleanly, attacker sends clean addr -> passes for wrong addr
     */
    function withdrawUnsafe(address to, uint256 amount) external {
        bool isOwnerRaw;
        assembly {
            let rawTo := calldataload(4)
            // owner stored clean in storage (always 20 bytes right-aligned)
            // rawTo might have dirty higher bits -> eq() fails for same address!
            isOwnerRaw := eq(rawTo, sload(owner.slot))
        }
        require(isOwnerRaw, "Not owner (raw check)");
        require(treasuryBalance >= amount, "Insufficient");
        treasuryBalance -= amount;
        // 'to' is Solidity-cleaned, so transfer goes to correct address
        payable(to).transfer(amount);
    }
    
    /**
     * @dev Type confusion via abi.encodePacked - ACTUALLY EXPLOITABLE
     * BUG #7: abi.encodePacked(uint128, uint128) = same bytes as abi.encodePacked(uint256)
     * keccak256 hash collision between completely different parameter types
     *
     * Example: registerPair(1, 2) -> bytes32(0x00..01 00..02) -> 32 bytes
     *          verifyAsUint256(0x00..01_00..02) -> same 32 bytes -> COLLISION!
     */
    function registerPair(uint128 tokenA, uint128 tokenB) external {
        require(isAdmin[msg.sender], "Not admin");
        // Packs as 16 bytes + 16 bytes = 32 bytes total
        bytes32 pairHash = keccak256(abi.encodePacked(tokenA, tokenB));
        whitelistHashes[pairHash] = true;
    }
    
    function verifyAsUint256(uint256 combinedValue) external view returns (bool) {
        // BUG #7: Packs as 32 bytes — identical to two uint128s concatenated!
        // tokenA=1, tokenB=2 matches uint256((1 << 128) | 2)
        bytes32 hash = keccak256(abi.encodePacked(combinedValue));
        return whitelistHashes[hash];
    }
    
    /**
     * @dev Dirty bits survive delegatecall boundary - ACTUALLY EXPLOITABLE
     * BUG #8: Raw calldata forwarded via delegatecall preserves dirty bits
     * Target contract receives full 32-byte values including dirty higher bits
     * If target uses assembly to read calldata, dirty bits affect its logic
     */
    function delegateWithRawCalldata(address target) external returns (bytes memory) {
        require(isAdmin[msg.sender], "Not admin");
        
        // Forward everything after selector+target (36 bytes) via delegatecall
        // Dirty bits in remaining calldata pass through to target
        bytes memory data;
        assembly {
            let dataLen := sub(calldatasize(), 36)
            data := mload(0x40)
            mstore(data, dataLen)
            calldatacopy(add(data, 32), 36, dataLen)
            mstore(0x40, add(add(data, 32), dataLen))
        }
        
        // BUG: delegatecall forwards raw bytes including dirty higher bits
        // Target contract's assembly reads see dirty data
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok, "Delegate failed");
        return result;
    }
}
