// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AdvancedSignatures
 * @dev Training Contract #61 - Signature Exploits (EIP-712, EIP-1271, EIP-2612)
 *
 * VULNERABILITY CATEGORIES:
 * 1. EIP-712 Domain Separator Replay (SIG-DOMAIN-01)
 * 2. EIP-1271 Fake Contract Signer (SIG-1271FAKE-01)
 * 3. Permit Replay Cross-Chain (SIG-PERMITREPLAY-01)
 * 4. Signature Malleability S-Value (SIG-MALLEABLE-01)
 * 5. ecrecover Zero Address (SIG-ECRECOVER0-01)
 * 6. EIP-2612 Permit Front-Run (SIG-PERMITFRONT-01)
 * 7. Nonce Gap Griefing (SIG-NONCEGAP-01)
 * 8. Deadline Manipulation (SIG-DEADLINE-01)
 * 9. Multi-Sig Reorg Vulnerability (SIG-MULTISIGREORG-01)
 * 10. Contract Wallet isValidSignature Spoof (SIG-ISVALID-01)
 * 11. Typed Data Hash Collision (SIG-TYPEHASH-01)
 * 12. Off-Chain Sig → On-Chain Replay (SIG-OFFCHAIN-01)
 * 13. Compact Signature (EIP-2098) Parsing (SIG-COMPACT-01)
 * 14. Meta-Transaction Griefing (SIG-METATX-01)
 * 15. Batch Permit Atomic Failure (SIG-BATCHPERMIT-01)
 * 16. SignatureChecker Fallback (SIG-CHECKER-01)
 * 17. CREATE2 + Signature Pre-Image (SIG-CREATE2SIG-01)
 * 18. Delegated Action Scope Escape (SIG-SCOPE-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): SIG-*, ecrecover, permit, EIP-712, malleability
 * - Engine 2 (deep-semantic): signature verification, replay protection
 * - Engine 13 (mev-analyzer): front-running permit, meta-tx griefing
 * - Engine 5 (compiler-vulns): ABI encoding edge cases
 */

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract AdvancedSignatureExploits {

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegator,address delegatee,uint256 scope,uint256 nonce,uint256 deadline)");

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => uint256) public nonces;
    
    string public name = "AdvancedSigToken";
    string public version = "1";
    address public owner;

    constructor() {
        owner = msg.sender;
        // BUG: DOMAIN_SEPARATOR computed once, doesn't include chainId dynamically
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            block.chainid,
            address(this)
        ));
    }

    // ========== VULN 1: EIP-712 Domain Separator Replay (SIG-DOMAIN-01) ==========

    // BUG #1: DOMAIN_SEPARATOR cached in constructor — invalid after chain fork
    function permit(
        address _owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        // VULN: uses cached DOMAIN_SEPARATOR
        // after chain fork (e.g., ETH/ETH-PoW), same sig valid on both chains
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH, _owner, spender, value, nonces[_owner]++, deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == _owner, "invalid sig");
        allowances[_owner][spender] = value;
    }

    // ========== VULN 2: EIP-1271 Fake Contract Signer (SIG-1271FAKE-01) ==========

    // BUG #2: contract signer always returns magic value
    function verifyContractSignature(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) external view returns (bool) {
        if (signer.code.length > 0) {
            // VULN: malicious contract always returns 0x1626ba7e
            // any hash + any signature = valid
            try IERC1271(signer).isValidSignature(hash, signature) returns (bytes4 magic) {
                return magic == 0x1626ba7e;
            } catch {
                return false;
            }
        }
        // EOA path
        return _recoverSigner(hash, signature) == signer;
    }

    // ========== VULN 3: Permit Replay Cross-Chain (SIG-PERMITREPLAY-01) ==========

    // BUG #3: permit signature from mainnet replayed on L2 with same contract address
    function permitCrossChain(
        address _owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s,
        uint256 targetChainId
    ) external {
        // VULN: checks targetChainId but DOMAIN_SEPARATOR was built with different chainId
        // if contract deployed at same address on multiple chains, sig replays
        require(targetChainId == block.chainid, "wrong chain");
        // Still uses cached DOMAIN_SEPARATOR from constructor
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(PERMIT_TYPEHASH, _owner, spender, value, nonces[_owner]++, deadline))
        ));
        require(ecrecover(digest, v, r, s) == _owner, "invalid");
        allowances[_owner][spender] = value;
    }

    // ========== VULN 4: Signature Malleability S-Value (SIG-MALLEABLE-01) ==========

    // BUG #4: ecrecover accepts both s-values (s and secp256k1.n - s)
    function verifySignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) 
        external pure returns (address) 
    {
        // VULN: no check that s <= secp256k1n/2
        // attacker can flip s-value to create second valid signature
        // replay if "signature used" mapping stores hash(v,r,s)
        return ecrecover(hash, v, r, s);
    }

    // ========== VULN 5: ecrecover Zero Address (SIG-ECRECOVER0-01) ==========

    // BUG #5: ecrecover returns address(0) for invalid signatures
    function authenticatedAction(bytes32 actionHash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(actionHash, v, r, s);
        // VULN: if actionHash is crafted to make ecrecover return 0x0
        // and target address is 0x0 (uninitialized), auth bypassed
        require(signer == owner, "not owner");
        // If owner == address(0), anyone can pass
    }

    // ========== VULN 6: EIP-2612 Permit Front-Run (SIG-PERMITFRONT-01) ==========

    // BUG #6: permit tx is public in mempool, anyone can front-run it
    function transferWithPermit(
        address from, address to, uint256 amount,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        // VULN: attacker sees this tx in mempool, extracts permit sig,
        // calls permit() separately → original tx reverts (nonce used)
        // but allowance is still set for attacker's benefit
        this.permit(from, msg.sender, amount, deadline, v, r, s);
        // If attacker front-ran permit, this reverts
        _transfer(from, to, amount);
    }

    // ========== VULN 7: Nonce Gap Griefing (SIG-NONCEGAP-01) ==========

    // BUG #7: attacker can increment someone's nonce to invalidate pending permits
    function incrementNonce() external {
        // VULN: anyone can burn their own nonce
        // griefing: user signs permit with nonce 5, attacker calls incrementNonce
        // for the user via another permit → nonce becomes 6 → original sig invalid
        nonces[msg.sender]++;
    }

    function cancelPermit(address target) external {
        // VULN: no access control on nonce invalidation
        nonces[target]++;
    }

    // ========== VULN 8: Deadline Manipulation (SIG-DEADLINE-01) ==========

    // BUG #8: permit with type(uint256).max deadline never expires
    function hasExpired(uint256 deadline) external view returns (bool) {
        // VULN: many users sign permits with max deadline for convenience
        // these permits are valid forever — if private key compromised later,
        // old permits still work
        return block.timestamp > deadline;
    }

    // ========== VULN 9: Multi-Sig Reorg Vulnerability (SIG-MULTISIGREORG-01) ==========

    mapping(bytes32 => uint256) public multiSigApprovals;
    uint256 public requiredApprovals = 3;

    // BUG #9: multi-sig approval not replay-protected across reorgs
    function approveMultiSig(bytes32 txHash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(txHash, v, r, s);
        require(signer != address(0), "invalid sig");
        // VULN: no block number or timestamp in signed message
        // after reorg, same approval can be replayed for different tx
        multiSigApprovals[txHash]++;
    }

    function executeMultiSig(bytes32 txHash, address target, bytes calldata data) external {
        require(multiSigApprovals[txHash] >= requiredApprovals, "not enough sigs");
        (bool ok, ) = target.call(data);
        require(ok, "execution failed");
    }

    // ========== VULN 10: Contract Wallet isValidSignature Spoof (SIG-ISVALID-01) ==========

    // BUG #10: upgradeable wallet can change isValidSignature implementation
    function trustContractSigner(address wallet, bytes32 hash, bytes calldata sig) external view returns (bool) {
        // VULN: wallet is upgradeable proxy → impl can change
        // at time T signature is valid, at T+1 impl changes to reject
        // or: impl changed to accept everything after original signer lost key
        (bool ok, bytes memory ret) = wallet.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, sig)
        );
        return ok && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    // ========== VULN 11: Typed Data Hash Collision (SIG-TYPEHASH-01) ==========

    // BUG #11: different struct types can produce same typeHash if names collide
    bytes32 public constant TYPEHASH_A = keccak256("Action(address user,uint256 amount)");
    // Intentionally same as TYPEHASH_A if struct name matches
    bytes32 public constant TYPEHASH_B = keccak256("Action(address user,uint256 amount)");

    function verifyTypedA(address user, uint256 amount, uint8 v, bytes32 r, bytes32 s) external view returns (address) {
        // VULN: TYPEHASH_A == TYPEHASH_B → signature for Action A is valid for Action B
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(TYPEHASH_A, user, amount))));
        return ecrecover(digest, v, r, s);
    }

    // ========== VULN 12: Off-Chain Sig → On-Chain Replay (SIG-OFFCHAIN-01) ==========

    mapping(bytes32 => bool) public usedSignatures;

    // BUG #12: off-chain signature stored by hash but hash doesn't include all context
    function executeOffChainAction(
        address target, bytes calldata data,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 sigHash = keccak256(abi.encodePacked(r, s, v));
        require(!usedSignatures[sigHash], "replay");
        usedSignatures[sigHash] = true;
        
        // VULN: sigHash only covers (r,s,v) not the actual message
        // different message + same sig (malleability) bypasses replay check
        bytes32 msgHash = keccak256(data);
        address signer = ecrecover(msgHash, v, r, s);
        require(signer == owner, "not owner");
        (bool ok, ) = target.call(data);
        require(ok);
    }

    // ========== VULN 13: Compact Signature (EIP-2098) Parsing (SIG-COMPACT-01) ==========

    // BUG #13: EIP-2098 encodes v into s, compact 64-byte format
    function recoverCompact(bytes32 hash, bytes calldata signature) external pure returns (address) {
        require(signature.length == 64, "not compact");
        bytes32 r = bytes32(signature[:32]);
        bytes32 vs = bytes32(signature[32:64]);
        // VULN: v recovery from vs high bit can fail if not properly masked
        uint8 v = uint8(uint256(vs) >> 255) + 27;
        bytes32 s = vs & bytes32(uint256(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff));
        // No s-value range check (malleability)
        return ecrecover(hash, v, r, s);
    }

    // ========== VULN 14: Meta-Transaction Griefing (SIG-METATX-01) ==========

    // BUG #14: relayer submits meta-tx but can manipulate gas
    function executeMetaTx(
        address from, address to, bytes calldata data,
        uint256 nonce_, uint8 v, bytes32 r, bytes32 s
    ) external returns (bool) {
        require(nonce_ == nonces[from], "bad nonce");
        bytes32 digest = keccak256(abi.encodePacked(from, to, data, nonce_));
        require(ecrecover(digest, v, r, s) == from, "bad sig");
        nonces[from]++;
        
        // VULN: relayer controls gas limit for inner call
        // can provide just enough gas for call to fail silently
        // nonce incremented → sig burned → user's tx effectively dropped
        (bool ok, ) = to.call{gas: gasleft() - 5000}(data);
        return ok; // Doesn't revert on failure
    }

    // ========== VULN 15: Batch Permit Atomic Failure (SIG-BATCHPERMIT-01) ==========

    // BUG #15: batch permit where one invalid sig reverts entire batch
    function batchPermit(
        address[] calldata owners,
        address[] calldata spenders,
        uint256[] calldata values,
        uint256[] calldata deadlines,
        uint8[] calldata vs, bytes32[] calldata rs, bytes32[] calldata ss
    ) external {
        for (uint256 i = 0; i < owners.length; i++) {
            // VULN: if any single permit in batch fails → entire batch reverts
            // attacker can invalidate batch by front-running one permit
            this.permit(owners[i], spenders[i], values[i], deadlines[i], vs[i], rs[i], ss[i]);
        }
    }

    // ========== VULN 16: SignatureChecker Fallback (SIG-CHECKER-01) ==========

    // BUG #16: OZ SignatureChecker.isValidSignatureNow fallback behavior
    function checkSignature(address signer, bytes32 hash, bytes memory sig) external view returns (bool) {
        if (signer.code.length > 0) {
            // VULN: if contract's isValidSignature reverts instead of returning,
            // some checkers treat revert as "not valid" but some propagate revert
            try IERC1271(signer).isValidSignature(hash, sig) returns (bytes4 val) {
                return val == 0x1626ba7e;
            } catch {
                return false; // Swallows OOG, treating it as "invalid"
            }
        }
        return _recoverSigner(hash, sig) == signer;
    }

    // ========== VULN 17: CREATE2 + Signature Pre-Image (SIG-CREATE2SIG-01) ==========

    // BUG #17: CREATE2 address predictable → signature pre-image attack
    function deployAndSign(bytes32 salt, bytes memory code) external returns (address) {
        address deployed;
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }
        // VULN: attacker precomputes deployed address
        // crafts signature where "signer" == future contract address
        // contract's isValidSignature returns true for any hash
        return deployed;
    }

    // ========== VULN 18: Delegated Action Scope Escape (SIG-SCOPE-01) ==========

    mapping(address => mapping(address => uint256)) public delegationScopes;

    // BUG #18: delegated signature has scope but scope isn't enforced in execution
    function delegateAction(
        address delegatee, uint256 scope, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(DELEGATION_TYPEHASH, msg.sender, delegatee, scope, nonces[msg.sender]++, deadline))
        ));
        require(ecrecover(digest, v, r, s) == msg.sender, "bad sig");
        // VULN: scope stored but never checked when delegatee acts
        delegationScopes[msg.sender][delegatee] = scope;
    }

    // ========== Helpers ==========

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        uint8 v; bytes32 r; bytes32 s;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balances[from] >= amount, "insufficient");
        balances[from] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner);
        balances[to] += amount;
    }
}
