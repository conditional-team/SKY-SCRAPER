// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CrossChainMessaging
 * @dev Training Contract #51 - Cross-Chain Messaging Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. LayerZero Adapter Replay (XMSG-LZ-REPLAY-01)
 * 2. LayerZero Untrusted Remote (XMSG-LZ-REMOTE-01)
 * 3. Wormhole VAA Forgery (XMSG-WH-FORGE-01)
 * 4. Wormhole Guardian Set Stale (XMSG-WH-GUARDIAN-01)
 * 5. Relayer Censorship (XMSG-RELAY-CENSOR-01)
 * 6. Message Ordering Exploit (XMSG-ORDER-01)
 * 7. Gas Limit Manipulation (XMSG-GAS-01)
 * 8. Double-Spend via Slow Finality (XMSG-DOUBLESPEND-01)
 * 9. Bridge Token Mint Overflow (XMSG-MINT-01)
 * 10. Source Chain Verification Skip (XMSG-SRCVERIFY-01)
 * 11. Refund Address Exploit (XMSG-REFUND-01)
 * 12. Payload Truncation Attack (XMSG-PAYLOAD-01)
 * 13. Multi-Sig Bridge Key Compromise (XMSG-MULTISIG-01)
 * 14. Nonce Gap DoS (XMSG-NONCE-01)
 * 15. Fee Estimation Grief (XMSG-FEEEST-01)
 * 16. Executor Specified Payload (XMSG-EXECUTOR-01)
 * 17. Blocked Message Queue Drain (XMSG-BLOCKED-01)
 * 18. Adapter Version Mismatch (XMSG-VERSION-01)
 * 19. Composed Message Reentrancy (XMSG-COMPOSED-01)
 * 20. Default Config Inherited Trust (XMSG-DEFAULTCFG-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): XMSG-*, replay, bridge, cross-chain
 * - Engine 2 (deep-semantic): message verification, nonce logic
 * - Engine 17 (cross-contract): multi-chain interactions
 * - Engine 5 (reentrancy-checker): composed message reentrancy
 */

interface ILayerZeroEndpoint {
    function send(uint16 dstChainId, bytes calldata destination, bytes calldata payload, address refundAddress, address zroPayment, bytes calldata adapterParams) external payable;
    function receivePayload(uint16 srcChainId, bytes calldata srcAddress, address dstAddress, uint64 nonce, uint256 gasLimit, bytes calldata payload) external;
}

interface ILayerZeroReceiver {
    function lzReceive(uint16 srcChainId, bytes calldata srcAddress, uint64 nonce, bytes calldata payload) external;
}

// ========== VULN 1: LayerZero Adapter Replay (XMSG-LZ-REPLAY-01) ==========

contract VulnerableLZBridge is ILayerZeroReceiver {
    ILayerZeroEndpoint public endpoint;
    mapping(uint16 => bytes) public trustedRemotes;
    mapping(address => uint256) public balances;
    address public owner;
    
    // Nonce tracking
    mapping(uint16 => mapping(bytes => uint64)) public lastNonce;
    
    // Blocked messages
    mapping(uint16 => mapping(bytes => mapping(uint64 => bytes32))) public blockedMessages;
    
    constructor(address _endpoint) {
        endpoint = ILayerZeroEndpoint(_endpoint);
        owner = msg.sender;
    }

    // BUG #1: no nonce validation, same message can be replayed
    function lzReceive(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external override {
        require(msg.sender == address(endpoint), "not endpoint");
        // VULN: nonce not checked against lastNonce, replay possible
        // attacker replays old successful bridge message to mint again
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 2: LayerZero Untrusted Remote (XMSG-LZ-REMOTE-01) ==========

    // BUG #2: trustedRemote not set for some chains, defaults to accepting any
    function setTrustedRemote(uint16 chainId, bytes calldata remote) external {
        require(msg.sender == owner);
        trustedRemotes[chainId] = remote;
    }

    function _isTrustedRemote(uint16 srcChainId, bytes calldata srcAddress) internal view returns (bool) {
        bytes memory trusted = trustedRemotes[srcChainId];
        // VULN: if trustedRemote is empty (not set), length == 0, comparison skipped
        // any source address accepted from un-configured chains
        if (trusted.length == 0) return true; // SHOULD return false
        return keccak256(trusted) == keccak256(srcAddress);
    }

    // ========== VULN 3: Wormhole VAA Forgery (XMSG-WH-FORGE-01) ==========

    struct VAA {
        uint8 version;
        uint32 guardianSetIndex;
        bytes signatures;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
    }

    mapping(bytes32 => bool) public consumedVAAs;
    uint32 public currentGuardianSetIndex;

    // BUG #3: VAA verification only checks signature count, not actual signatures
    function processVAA(bytes calldata vaaBytes) external {
        VAA memory vaa = _parseVAA(vaaBytes);
        bytes32 hash = keccak256(vaaBytes);
        require(!consumedVAAs[hash], "already consumed");
        
        // VULN: only checks signature count >= 13 (2/3 of 19 guardians)
        // doesn't actually verify ECDSA signatures against guardian public keys
        require(vaa.signatures.length >= 13 * 66, "not enough sigs");
        // Missing: ecrecover validation against guardian set
        
        consumedVAAs[hash] = true;
        _executeVAAPayload(vaa.payload);
    }

    // ========== VULN 4: Wormhole Guardian Set Stale (XMSG-WH-GUARDIAN-01) ==========

    // BUG #4: old guardian set still accepted after rotation
    function verifyGuardianSet(uint32 guardianSetIndex) internal view returns (bool) {
        // VULN: accepts both current and previous guardian set
        // compromised old guardians can still sign valid VAAs
        return guardianSetIndex >= currentGuardianSetIndex - 1;
    }

    // ========== VULN 5: Relayer Censorship (XMSG-RELAY-CENSOR-01) ==========

    mapping(address => bool) public relayers;

    // BUG #5: single relayer can censor messages by not delivering them
    function deliverMessage(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload,
        bytes calldata proof
    ) external {
        // VULN: only registered relayers can deliver, no permissionless fallback
        require(relayers[msg.sender], "not relayer");
        // If relayer goes offline or censors, messages are stuck
        _processMessage(srcChainId, srcAddress, nonce, payload);
    }

    // ========== VULN 6: Message Ordering Exploit (XMSG-ORDER-01) ==========

    // BUG #6: messages processed out of order allow double-spend
    // message 1: transfer 100 tokens A→B, message 2: spend tokens on B
    // if message 2 arrives first, attacker can front-run with their own msg
    function processMessageUnordered(uint16 srcChainId, uint64 nonce, bytes calldata payload) external {
        // VULN: no sequential nonce enforcement
        // messages can be delivered in any order
        _processMessage(srcChainId, "", nonce, payload);
    }

    // ========== VULN 7: Gas Limit Manipulation (XMSG-GAS-01) ==========

    // BUG #7: user specifies gas limit for destination execution
    // too low = message fails but tokens already burned on source
    function sendCrossChain(
        uint16 dstChainId,
        bytes calldata receiver,
        uint256 amount,
        uint256 gasForDestination
    ) external payable {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        
        // VULN: no minimum gas validation
        // setting gasForDestination too low causes destination to revert
        // tokens burned on source but never minted on destination
        bytes memory adapterParams = abi.encodePacked(uint16(1), gasForDestination);
        bytes memory payload = abi.encode(msg.sender, amount);
        
        endpoint.send{value: msg.value}(
            dstChainId, receiver, payload, msg.sender, address(0), adapterParams
        );
    }

    // ========== VULN 8: Double-Spend via Slow Finality (XMSG-DOUBLESPEND-01) ==========

    mapping(bytes32 => bool) public processedTxHashes;

    // BUG #8: bridge accepts message based on source tx hash
    // but source chain reorg can invalidate the original tx
    function processWithTxHash(bytes32 sourceTxHash, bytes calldata payload) external {
        require(relayers[msg.sender], "not relayer");
        require(!processedTxHashes[sourceTxHash], "already processed");
        // VULN: source chain reorg may invalidate sourceTxHash
        // attacker: send tx → bridge mints → reorg removes original tx → profit
        processedTxHashes[sourceTxHash] = true;
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 9: Bridge Token Mint Overflow (XMSG-MINT-01) ==========

    mapping(address => uint256) public bridgeMinted;
    uint256 public mintCap = 1_000_000e18;

    // BUG #9: per-token cap but total bridge mints not tracked globally
    function processMint(address token, address to, uint256 amount) internal {
        bridgeMinted[token] += amount;
        // VULN: per-token cap, but attacker uses different token addresses
        // same underlying asset bridged under multiple token addresses
        require(bridgeMinted[token] <= mintCap, "cap");
        balances[to] += amount;
    }

    // ========== VULN 10: Source Chain Verification Skip (XMSG-SRCVERIFY-01) ==========

    // BUG #10: message from unexpected source chain accepted
    function _processMessage(uint16 srcChainId, bytes memory srcAddress, uint64 nonce, bytes calldata payload) internal {
        // VULN: no check that srcChainId is a supported/expected chain
        // attacker deploys on unsupported chain, sends crafted message
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 11: Refund Address Exploit (XMSG-REFUND-01) ==========

    // BUG #11: refund address for failed messages goes to user-specified address
    // attacker sets refund to contract that re-enters bridge
    function sendWithRefund(uint16 dstChainId, bytes calldata payload, address refundAddr) external payable {
        // VULN: refundAddr can be a contract with fallback that re-enters
        // if message fails, refund triggers reentrancy
        endpoint.send{value: msg.value}(
            dstChainId, trustedRemotes[dstChainId], payload, refundAddr, address(0), ""
        );
    }

    // ========== VULN 12: Payload Truncation Attack (XMSG-PAYLOAD-01) ==========

    // BUG #12: payload decoded with abi.decode doesn't validate length
    function processPayload(bytes calldata payload) external {
        // VULN: extra bytes appended to payload are ignored by abi.decode
        // attacker appends extra data that passes hash check but decodes differently
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        // Extra bytes in payload could bypass dedup checks (different hash)
        balances[to] += amount;
    }

    // ========== VULN 13: Multi-Sig Bridge Key Compromise (XMSG-MULTISIG-01) ==========

    address[] public signers;
    uint256 public threshold;

    // BUG #13: 3-of-5 multisig for bridge, but 3 signers are same entity
    function executeMultisig(bytes calldata payload, bytes[] calldata signatures) external {
        require(signatures.length >= threshold, "not enough sigs");
        // VULN: doesn't check for duplicate signers
        // same signer can sign multiple times
        for (uint256 i = 0; i < signatures.length; i++) {
            // No dedup check on recovered signer addresses
            bytes32 hash = keccak256(payload);
            (uint8 v, bytes32 r, bytes32 s) = _splitSig(signatures[i]);
            address signer = ecrecover(hash, v, r, s);
            require(_isSigner(signer), "not signer");
        }
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 14: Nonce Gap DoS (XMSG-NONCE-01) ==========

    mapping(uint16 => uint64) public expectedNonce;

    // BUG #14: strict nonce ordering means one blocked message blocks all subsequent
    function processStrictOrdered(uint16 srcChainId, uint64 nonce, bytes calldata payload) external {
        // VULN: if nonce 5 is blocked, nonces 6, 7, 8... all stall
        // attacker intentionally sends un-processable message at nonce N
        // all future messages from that chain are stuck
        require(nonce == expectedNonce[srcChainId], "wrong nonce");
        expectedNonce[srcChainId]++;
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 15: Fee Estimation Grief (XMSG-FEEEST-01) ==========

    // BUG #15: attacker sends many tiny messages to drain estimator
    mapping(uint16 => uint256) public estimatedFees;

    function estimateFee(uint16 dstChainId, bytes calldata payload) external view returns (uint256) {
        // VULN: fee estimation doesn't account for bursty traffic
        // attacker sends 1000 tiny messages, actual cost exceeds collected fees
        return estimatedFees[dstChainId]; // static, not dynamic
    }

    // ========== VULN 16: Executor Specified Payload (XMSG-EXECUTOR-01) ==========

    // BUG #16: executor/relayer can modify payload before delivery
    function executeWithPayload(bytes calldata originalPayload, bytes calldata executorPayload) external {
        require(relayers[msg.sender], "not relayer");
        // VULN: using executorPayload instead of verified originalPayload
        // malicious relayer swaps recipient or amount
        (address to, uint256 amount) = abi.decode(executorPayload, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 17: Blocked Message Queue Drain (XMSG-BLOCKED-01) ==========

    // BUG #17: retrying blocked messages doesn't re-verify source
    function retryMessage(uint16 srcChainId, bytes calldata srcAddress, uint64 nonce) external {
        bytes32 payloadHash = blockedMessages[srcChainId][srcAddress][nonce];
        require(payloadHash != bytes32(0), "no blocked message");
        // VULN: retry uses cached payload hash without re-verification
        // if source contract was compromised, retry still executes bad message
        delete blockedMessages[srcChainId][srcAddress][nonce];
        // Execute with potentially malicious payload
    }

    // ========== VULN 18: Adapter Version Mismatch (XMSG-VERSION-01) ==========

    uint16 public adapterVersion = 1;

    // BUG #18: source and destination use different adapter param versions
    function sendWithAdapterV2(uint16 dstChainId, bytes calldata payload) external payable {
        // VULN: sends V2 adapter params, but destination may only support V1
        // V2 includes airdrop params that V1 ignores => tokens lost
        bytes memory adapterParams = abi.encodePacked(
            uint16(2), // V2 adapter
            uint256(200000), // gas
            uint256(1 ether), // airdrop amount
            msg.sender // airdrop address
        );
        endpoint.send{value: msg.value}(
            dstChainId, trustedRemotes[dstChainId], payload, msg.sender, address(0), adapterParams
        );
    }

    // ========== VULN 19: Composed Message Reentrancy (XMSG-COMPOSED-01) ==========

    // BUG #19: composed messages allow cross-contract calls that re-enter bridge
    function lzCompose(
        address from,
        bytes32 guid,
        bytes calldata message,
        address executor,
        bytes calldata extraData
    ) external {
        // VULN: external call from composed message can re-enter
        (address target, bytes memory callData) = abi.decode(message, (address, bytes));
        // Reentrancy: target calls back into bridge during compose
        (bool ok, ) = target.call(callData);
        require(ok, "compose failed");
    }

    // ========== VULN 20: Default Config Inherited Trust (XMSG-DEFAULTCFG-01) ==========

    mapping(uint16 => address) public customConfigs;

    // BUG #20: OApp inherits default config if custom not set
    // default config may have permissive settings (e.g., required DVNs = 0)
    function getConfig(uint16 chainId) external view returns (address) {
        if (customConfigs[chainId] == address(0)) {
            // VULN: falls back to default which may have 0 DVN requirement
            // messages accepted without any validation
            return address(0); // default = no verification
        }
        return customConfigs[chainId];
    }

    // ========== Helpers ==========

    function _parseVAA(bytes calldata) internal pure returns (VAA memory vaa) {
        // Simplified—real parsing is more complex
        return vaa;
    }

    function _executeVAAPayload(bytes memory payload) internal {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }

    function _splitSig(bytes calldata sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        r = bytes32(sig[:32]);
        s = bytes32(sig[32:64]);
        v = uint8(bytes1(sig[64:65]));
    }

    function _isSigner(address addr) internal view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == addr) return true;
        }
        return false;
    }

    function addRelayer(address r) external { require(msg.sender == owner); relayers[r] = true; }
    function addSigner(address s) external { require(msg.sender == owner); signers.push(s); }
    function setThreshold(uint256 t) external { require(msg.sender == owner); threshold = t; }
    function setConfig(uint16 chainId, address cfg) external { require(msg.sender == owner); customConfigs[chainId] = cfg; }
}
