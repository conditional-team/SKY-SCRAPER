// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BridgeCrossChainAdvanced
 * @dev Training Contract #35 - Bridge / Cross-Chain Advanced Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Locked Token Bridge Exploit (BRIDGE-ADV-01)
 * 2. Validator Set Manipulation (BRIDGE-ADV-02)
 * 3. ZK-SNARK Verification Bypass (BRIDGE-ADV-03)
 * 4. ZK-STARK Verification Bypass (BRIDGE-ADV-04)
 * 5. Sidechain Oracle Lag Exploit (BRIDGE-ADV-05)
 * 6. Cross-Rollup Exploit (BRIDGE-ADV-06)
 * 7. L2 Withdraw Miscalc (BRIDGE-ADV-07)
 * 8. Cross-Chain Reward Duplication (BRIDGE-ADV-08)
 * 9. Bridge Fee Miscalc (BRIDGE-ADV-09)
 * 10. Validator Bribery (BRIDGE-ADV-10)
 * 11. Cross-Chain Mint Replay (BRIDGE-ADV-11)
 * 12. Orchestrator Cross-Chain Flaw (BRIDGE-ADV-12)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): BRIDGE-ADV-01→12
 * - Engine 32 (l2-message-checker): cross-chain message flaws
 * - Engine 25 (finality-checker): finality assumption errors
 *
 * REAL-WORLD: Ronin $624M, Wormhole $320M, Nomad $190M, Harmony $100M
 */

// ========== VULN 1: Locked Token Bridge (BRIDGE-ADV-01) ==========

contract VulnerableBridge {
    mapping(address => uint256) public lockedTokens;
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => bool) public validators;
    uint256 public validatorCount;
    uint256 public requiredConfirmations = 2;
    address public orchestrator;

    uint256 public bridgeFee = 100; // basis points
    uint256 public constant FEE_DENOMINATOR = 10000;
    uint256 public totalLocked;
    uint256 public totalMintedOnL2; // tracked locally (wrong)

    mapping(bytes32 => uint256) public confirmations;
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;

    event Locked(address indexed token, address indexed sender, uint256 amount, uint256 destChain);
    event Minted(address indexed token, address indexed recipient, uint256 amount);

    constructor() {
        orchestrator = msg.sender;
    }

    // BUG #1: minted on L2 can exceed locked on L1
    // No cross-chain state verification — L2 minter trusts any message
    function lock(address token, uint256 amount, uint256 destChain) external {
        lockedTokens[token] += amount;
        totalLocked += amount;
        // VULN: no proof that L2 hasn't already minted more than locked
        emit Locked(token, msg.sender, amount, destChain);
    }

    function mintOnL2(address token, address recipient, uint256 amount, bytes32 messageHash) external {
        require(validators[msg.sender], "not validator");
        // VULN: amount not verified against actual locked amount on L1
        // Multiple validators can confirm different amounts
        if (!hasConfirmed[messageHash][msg.sender]) {
            hasConfirmed[messageHash][msg.sender] = true;
            confirmations[messageHash]++;
        }

        if (confirmations[messageHash] >= requiredConfirmations) {
            require(!processedMessages[messageHash], "already processed");
            processedMessages[messageHash] = true;
            totalMintedOnL2 += amount;
            emit Minted(token, recipient, amount);
        }
    }

    // BUG #2: BRIDGE-ADV-02 — validator set manipulation
    function addValidator(address validator) external {
        // VULN: no timelock, no multi-sig requirement
        require(msg.sender == orchestrator, "not orchestrator");
        validators[validator] = true;
        validatorCount++;
    }

    function removeValidator(address validator) external {
        require(msg.sender == orchestrator, "not orchestrator");
        validators[validator] = false;
        validatorCount--;
        // VULN: can reduce below requiredConfirmations threshold
    }

    // BUG #3: BRIDGE-ADV-03 — ZK-SNARK verification bypass
    function verifyZKProof(
        uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c,
        uint256[] memory publicInputs
    ) external pure returns (bool) {
        // VULN: verifier doesn't correctly check proof
        // Missing pairing check, accepts any non-zero proof
        if (a[0] != 0 && b[0][0] != 0 && c[0] != 0) {
            return true; // always passes with non-zero values
        }
        return false;
    }

    // BUG #4: BRIDGE-ADV-04 — ZK-STARK incomplete verification
    function verifySTARKProof(
        bytes calldata proof, uint256[] calldata publicInputs
    ) external pure returns (bool) {
        // VULN: only checks proof length, not actual validity
        require(proof.length > 64, "proof too short");
        require(publicInputs.length > 0, "no inputs");
        // Missing FRI verification, missing constraint checks
        return true;
    }

    // BUG #5: BRIDGE-ADV-05 — sidechain oracle lag
    mapping(address => uint256) public sidechainPrices;
    mapping(address => uint256) public mainchainPrices;
    mapping(address => uint256) public lastSidechainUpdate;

    function updateSidechainPrice(address token, uint256 price) external {
        sidechainPrices[token] = price;
        lastSidechainUpdate[token] = block.timestamp;
        // VULN: sidechain price can be minutes/hours behind mainchain
        // Creating arbitrage window
    }

    function getArbitrageOpportunity(address token) external view returns (int256) {
        // VULN: exposes the lag explicitly
        return int256(mainchainPrices[token]) - int256(sidechainPrices[token]);
    }

    // BUG #6: BRIDGE-ADV-06 — cross-rollup state claim without proof
    function claimFromRollupB(
        address token, uint256 amount, uint256 rollupBBlockNumber
    ) external {
        // VULN: no Merkle proof against rollup B's state root
        // Attacker claims arbitrary amount from rollup B
        emit Minted(token, msg.sender, amount);
    }

    // BUG #7: BRIDGE-ADV-07 — L2→L1 withdrawal amount miscalc
    function withdrawToL1(address token, uint256 l2Amount) external {
        uint256 fee = l2Amount * bridgeFee / FEE_DENOMINATOR;
        // VULN: fee deducted from already-fee-deducted amount on some paths
        // Or gas compensation not accounted for
        uint256 l1Amount = l2Amount - fee;
        // VULN: L1 and L2 use different decimals (e.g., USDC 6 vs 18)
        lockedTokens[token] -= l1Amount; // underflow if decimals mismatch
    }

    // BUG #8: BRIDGE-ADV-08 — cross-chain reward duplication
    mapping(address => mapping(uint256 => bool)) public rewardClaimed;

    function claimRewardOnChain(uint256 epoch) external {
        // VULN: claimed flag is per-chain — same user can claim on chain A and chain B
        require(!rewardClaimed[msg.sender][epoch], "already claimed");
        rewardClaimed[msg.sender][epoch] = true;
        // No cross-chain state check
    }

    // BUG #9: BRIDGE-ADV-09 — bridge fee overflow
    function calculateBridgeFee(uint256 amount) external view returns (uint256) {
        // VULN: fee * amount can overflow, or fee on already-deducted amount
        return amount * bridgeFee / FEE_DENOMINATOR;
    }

    // BUG #10: BRIDGE-ADV-10 — validator bribery economics
    function getMinBribeCost() external view returns (uint256) {
        // VULN: bribery cost = requiredConfirmations * validator_reward
        // If bridge TVL >> bribe cost, attack is profitable
        return requiredConfirmations * 1 ether;
    }

    // BUG #11: BRIDGE-ADV-11 — cross-chain mint replay
    function mintFromMessage(bytes32 messageHash, uint256 amount, uint256 nonce) external {
        // VULN: nonce not tracked, same message replayable
        require(validators[msg.sender], "not validator");
        // Missing: require(!usedNonces[nonce]) or require(!processedMessages[messageHash])
        emit Minted(address(0), msg.sender, amount);
    }

    // BUG #12: BRIDGE-ADV-12 — centralized orchestrator flaw
    function relayMessage(
        address token, address recipient, uint256 amount, uint256 srcChain
    ) external {
        // VULN: orchestrator is single point of failure
        require(msg.sender == orchestrator, "not orchestrator");
        // Orchestrator can reorder, censor, or fabricate messages
        // No decentralized verification
        emit Minted(token, recipient, amount);
    }
}
