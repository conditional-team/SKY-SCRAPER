// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PreconfBasedRollup
 * @dev Training Contract #26 - Based Rollup Preconfirmation & DA Exploits
 *
 * Simulates a based rollup with preconfirmation promises, L1 proposer selection,
 * data availability commitments, and cross-L2 atomic operations — all exploitable.
 *
 * VULNERABILITY CATEGORIES:
 * 1.  Preconf Promise Violation — proposer commits to include tx but reneges
 * 2.  Proposer MEV Extraction — L1 proposer reorders preconfirmed txs for profit
 * 3.  Double-Spend Window — spend on L2 then L1 reorg invalidates preconf
 * 4.  Preconf Censorship — proposer selectively excludes valid preconfirmed txs
 * 5.  Preconf Timing Exploit — commit to preconf, wait for price move, then decide
 * 6.  DA Withholding — post commitment but withhold actual data blobs
 * 7.  Blob Commitment Mismatch — KZG commitment doesn't match actual blob data
 * 8.  DA Offline Fallback — external DA layer goes down, no fallback mechanism
 * 9.  Cross-L2 Partial Execution — atomic bundle across L2s partially fails
 * 10. Cross-L2 Front-run — see pending cross-L2 tx, front-run on destination L2
 * 11. Shared Sequencer Unbundling — shared sequencer breaks atomic bundle guarantees
 * 12. Proposer Bond Drain — slash proposer bond repeatedly via manufactured violations
 *
 * REAL-WORLD CONTEXT:
 * - Based rollup proposals (Justin Drake, Ethereum Foundation)
 * - Espresso shared sequencer, Astria, Radius
 * - EIP-4844 blob transactions and KZG commitments
 * - EigenDA, Celestia, Avail DA layers
 * - Cross-L2 protocols: Across, Connext, Polymer
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1: Pattern DB (PRECONF-01..05, DA-01..04, CROSSATOM-01..03)
 * - Engine 5: Bleeding Edge (Frontier2026 — PreconfViolation, BasedProposerMEV, DAWithholding, CrossL2PartialExec)
 * - Engine 10: Exploit Synth (PreconfViolation attack synthesis)
 * - Engine 12: Fuzzing (PreconfExploit, DAWithholding, CrossL2Atomic combo types)
 * - Engine 8: Composability Checker (DALayer external class)
 * - Engine 6: MEV Analyzer (proposer reordering patterns)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 15_SandwichableView (MEV extraction patterns)
 * - Links to 17_L2SequencerExploit (L2 sequencer manipulation)
 * - Links to 19_BridgeOracleManipulation (cross-chain message attacks)
 * - Links to 23_IntentMEV (cross-domain MEV, solver collusion)
 */

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// ========== INTERFACES ==========

interface IDAOracle {
    function verifyBlob(bytes32 commitment, bytes calldata proof) external view returns (bool);
    function isDALayerOnline() external view returns (bool);
    function getBlobData(bytes32 commitment) external view returns (bytes memory);
}

interface ISharedSequencer {
    function submitBundle(bytes[] calldata txs, uint256[] calldata chainIds) external returns (bytes32 bundleId);
    function getBundleStatus(bytes32 bundleId) external view returns (uint8 status);
}

// 🔗 CHAIN: Links to 17_L2SequencerExploit — sequencer manipulation patterns
// 🔗 CHAIN: Links to 23_IntentMEV — cross-domain MEV extraction

// ========== PRECONFIRMATION REGISTRY (VULNERABLE) ==========

contract PreconfirmationRegistry {

    struct Preconfirmation {
        bytes32 txHash;
        address proposer;
        uint256 promisedSlot;
        uint256 timestamp;
        uint256 tip;
        bool fulfilled;
        bool slashed;
    }

    struct Proposer {
        uint256 bond;
        uint256 reputationScore;
        uint256 totalPreconfs;
        uint256 violations;
        bool active;
    }

    mapping(bytes32 => Preconfirmation) public preconfs;
    mapping(address => Proposer) public proposers;
    mapping(uint256 => address) public slotProposers; // slot => proposer
    mapping(uint256 => bytes32[]) public slotPreconfs; // slot => preconf hashes

    uint256 public minBond = 32 ether;
    uint256 public slashPercentage = 10; // VULN #12: Only 10% slash per violation
    uint256 public preconfWindow = 12; // seconds — 1 slot

    event PreconfIssued(bytes32 indexed txHash, address indexed proposer, uint256 slot);
    event PreconfFulfilled(bytes32 indexed txHash, uint256 slot);
    event PreconfViolation(bytes32 indexed txHash, address indexed proposer, uint256 slashAmount);
    event ProposerRegistered(address indexed proposer, uint256 bond);

    // ========== PROPOSER MANAGEMENT ==========

    /// @notice Register as a preconf proposer
    function registerProposer() external payable {
        require(msg.value >= minBond, "Insufficient bond");
        require(!proposers[msg.sender].active, "Already active");

        proposers[msg.sender] = Proposer({
            bond: msg.value,
            reputationScore: 100,
            totalPreconfs: 0,
            violations: 0,
            active: true
        });

        emit ProposerRegistered(msg.sender, msg.value);
    }

    // ========== PRECONFIRMATION (VULNERABLE) ==========

    /// @notice Issue a preconfirmation promise
    // VULN #1: No enforcement mechanism — proposer can promise and renege
    // VULN #4: Proposer can choose which txs to preconfirm (censorship)
    function issuePreconf(
        bytes32 txHash,
        uint256 targetSlot
    ) external payable {
        Proposer storage prop = proposers[msg.sender];
        require(prop.active, "Not active proposer");
        require(slotProposers[targetSlot] == msg.sender || slotProposers[targetSlot] == address(0), "Not slot proposer");

        // VULN #5: No commitment deadline — proposer can wait to see price movements
        // BUG: No check that targetSlot is in the future
        // BUG: No maximum preconfs per slot (can overcommit)

        preconfs[txHash] = Preconfirmation({
            txHash: txHash,
            proposer: msg.sender,
            promisedSlot: targetSlot,
            timestamp: block.timestamp,
            tip: msg.value,
            fulfilled: false,
            slashed: false
        });

        slotPreconfs[targetSlot].push(txHash);
        slotProposers[targetSlot] = msg.sender;
        prop.totalPreconfs++;

        emit PreconfIssued(txHash, msg.sender, targetSlot);
    }

    /// @notice Report that a preconf was included in a block
    // VULN #1: Self-reporting — proposer can claim fulfillment without proof
    function reportFulfillment(bytes32 txHash) external {
        Preconfirmation storage pc = preconfs[txHash];
        require(pc.proposer == msg.sender, "Not proposer");
        // BUG: No SPV proof that tx was actually included
        // BUG: No block number check against promised slot
        // VULN #2: Proposer may have reordered tx for MEV before including
        pc.fulfilled = true;
        emit PreconfFulfilled(txHash, pc.promisedSlot);
    }

    /// @notice Slash a proposer for preconf violation
    // VULN #12: Slash amount too low — profitable to violate
    // VULN #1: Relies on external reporter — no automatic detection
    function slashProposer(bytes32 txHash) external {
        Preconfirmation storage pc = preconfs[txHash];
        require(!pc.fulfilled, "Was fulfilled");
        require(!pc.slashed, "Already slashed");
        // BUG: No time check — can slash immediately without waiting for inclusion window

        Proposer storage prop = proposers[pc.proposer];
        // VULN #12: 10% slash — if MEV profit > 10% of bond, violation is profitable
        uint256 slashAmount = (prop.bond * slashPercentage) / 100;
        prop.bond -= slashAmount;
        prop.violations++;

        pc.slashed = true;

        // BUG: Slash reward goes to reporter — incentivizes manufactured violations
        // VULN #12: Reporter can front-run the slot to guarantee violation
        (bool ok, ) = msg.sender.call{value: slashAmount}("");
        require(ok, "Slash payout failed");

        emit PreconfViolation(txHash, pc.proposer, slashAmount);
    }

    /// @notice Check if proposer should be deactivated
    // BUG: Reputation score easily gamed
    function updateReputation(address proposer) external {
        Proposer storage prop = proposers[proposer];
        if (prop.violations > 3) {
            // BUG: Just deactivates — doesn't seize remaining bond
            prop.active = false;
        }
        // BUG: Reputation score not actually used in preconf acceptance
        if (prop.totalPreconfs > 0) {
            prop.reputationScore = ((prop.totalPreconfs - prop.violations) * 100) / prop.totalPreconfs;
        }
    }
}

// ========== DATA AVAILABILITY MANAGER (VULNERABLE) ==========

contract DAManager {

    struct BlobCommitment {
        bytes32 kzgCommitment;
        address submitter;
        uint256 timestamp;
        bool verified;
        uint256 challengeDeadline;
        bool challenged;
    }

    mapping(bytes32 => BlobCommitment) public blobs;
    IDAOracle public daOracle;
    uint256 public challengePeriod = 1 hours; // VULN #6: Too short for DA verification

    bool public daLayerOnline = true; // VULN #8: Manual flag, not auto-detected

    event BlobSubmitted(bytes32 indexed commitment, address indexed submitter);
    event BlobChallenged(bytes32 indexed commitment, address indexed challenger);
    event BlobVerified(bytes32 indexed commitment);

    constructor(address _daOracle) {
        daOracle = IDAOracle(_daOracle);
    }

    // ========== BLOB SUBMISSION (VULNERABLE) ==========

    /// @notice Submit a KZG commitment for a data blob
    // VULN #6: Can submit commitment without actually posting blob data
    // VULN #7: No validation that commitment matches actual data
    function submitBlob(bytes32 kzgCommitment) external {
        // BUG: No proof that actual data was posted anywhere
        // VULN #6: Just records commitment — data may never be available

        blobs[kzgCommitment] = BlobCommitment({
            kzgCommitment: kzgCommitment,
            submitter: msg.sender,
            timestamp: block.timestamp,
            verified: false,
            challengeDeadline: block.timestamp + challengePeriod,
            challenged: false
        });

        emit BlobSubmitted(kzgCommitment, msg.sender);
    }

    /// @notice Challenge a blob commitment
    // VULN #7: Challenge mechanism is weak — hard to prove data withholding
    function challengeBlob(bytes32 commitment, bytes calldata proof) external {
        BlobCommitment storage blob = blobs[commitment];
        require(block.timestamp <= blob.challengeDeadline, "Challenge period over");
        require(!blob.challenged, "Already challenged");

        // VULN #7: Oracle verification may not check actual data content
        // BUG: If DA layer is down, challenge always fails
        bool invalid = !daOracle.verifyBlob(commitment, proof);

        if (invalid) {
            blob.challenged = true;
            emit BlobChallenged(commitment, msg.sender);
            // BUG: No slashing of submitter for invalid blob
        }
    }

    /// @notice Auto-verify after challenge period
    // VULN #6: Absence of challenge != data is available
    function autoVerify(bytes32 commitment) external {
        BlobCommitment storage blob = blobs[commitment];
        require(block.timestamp > blob.challengeDeadline, "Challenge period active");
        require(!blob.challenged, "Was challenged");

        // VULN #6: Optimistic verification — assumes data is available if no challenge
        // BUG: Nobody may have checked — doesn't mean data exists
        blob.verified = true;
        emit BlobVerified(commitment);
    }

    /// @notice Check DA layer status
    // VULN #8: No fallback when external DA goes offline
    function checkDAStatus() external {
        // BUG: Try/catch swallows the real error
        try daOracle.isDALayerOnline() returns (bool online) {
            daLayerOnline = online;
        } catch {
            // VULN #8: On error, assumes DA is still online
            // Should halt operations, instead continues with stale assumption
            daLayerOnline = true; // DANGEROUS default
        }
    }

    /// @notice Submit blob even when DA is offline
    // VULN #8: No check for DA status before accepting blobs
    function submitBlobUnchecked(bytes32 commitment) external {
        // BUG: Doesn't check daLayerOnline at all
        blobs[commitment] = BlobCommitment({
            kzgCommitment: commitment,
            submitter: msg.sender,
            timestamp: block.timestamp,
            verified: false,
            challengeDeadline: block.timestamp + challengePeriod,
            challenged: false
        });
    }
}

// ========== CROSS-L2 ATOMIC EXECUTOR (VULNERABLE) ==========

contract CrossL2AtomicExecutor is ReentrancyGuard {

    struct AtomicBundle {
        bytes32 bundleId;
        address initiator;
        uint256[] chainIds;
        bytes[] callDatas;
        uint256 timestamp;
        uint8 status; // 0=pending, 1=executing, 2=completed, 3=partial, 4=failed
        uint256 executedCount;
        uint256 totalOps;
    }

    mapping(bytes32 => AtomicBundle) public bundles;
    ISharedSequencer public sharedSequencer;

    // Chain bridges
    mapping(uint256 => address) public chainBridges;

    event BundleSubmitted(bytes32 indexed bundleId, uint256 totalOps);
    event BundlePartialExec(bytes32 indexed bundleId, uint256 executedCount, uint256 totalOps);
    event BundleFailed(bytes32 indexed bundleId, uint256 failedAt);

    constructor(address _sequencer) {
        sharedSequencer = ISharedSequencer(_sequencer);
    }

    // ========== BUNDLE SUBMISSION (VULNERABLE) ==========

    /// @notice Submit atomic cross-L2 bundle
    // VULN #9: Not truly atomic — partial execution possible
    // VULN #11: Shared sequencer can unbundle operations
    function submitAtomicBundle(
        uint256[] calldata chainIds,
        bytes[] calldata callDatas
    ) external nonReentrant returns (bytes32) {
        require(chainIds.length == callDatas.length, "Length mismatch");
        require(chainIds.length > 0, "Empty bundle");

        bytes32 bundleId = keccak256(abi.encodePacked(msg.sender, block.timestamp, chainIds.length));

        // VULN #11: Submits to shared sequencer which may unbundle
        // BUG: No atomicity guarantee — sequencer processes each tx independently
        bytes32 seqBundleId = sharedSequencer.submitBundle(callDatas, chainIds);

        bundles[bundleId] = AtomicBundle({
            bundleId: seqBundleId,
            initiator: msg.sender,
            chainIds: chainIds,
            callDatas: callDatas,
            timestamp: block.timestamp,
            status: 0, // pending
            executedCount: 0,
            totalOps: chainIds.length
        });

        emit BundleSubmitted(bundleId, chainIds.length);
        return bundleId;
    }

    /// @notice Execute bundle operations one by one
    // VULN #9: Sequential execution — if one fails, previous already executed
    // VULN #10: Each cross-chain message visible in mempool
    function executeBundle(bytes32 bundleId) external nonReentrant {
        AtomicBundle storage bundle = bundles[bundleId];
        require(bundle.status == 0, "Not pending");
        bundle.status = 1; // executing

        for (uint256 i = 0; i < bundle.totalOps; i++) {
            address bridge = chainBridges[bundle.chainIds[i]];
            require(bridge != address(0), "No bridge for chain");

            // VULN #10: Each message sent separately — can be front-run
            // BUG: No rollback of previous operations if this one fails
            (bool ok, ) = bridge.call(bundle.callDatas[i]);

            if (ok) {
                bundle.executedCount++;
            } else {
                // VULN #9: Partial execution — some chains got the tx, others didn't
                bundle.status = 3; // partial
                emit BundlePartialExec(bundleId, bundle.executedCount, bundle.totalOps);
                // BUG: No compensating transactions for already-executed ops
                return;
            }
        }

        bundle.status = 2; // completed
    }

    /// @notice "Rollback" a partially executed bundle
    // BUG: Can't actually rollback cross-chain state changes
    function rollbackBundle(bytes32 bundleId) external {
        AtomicBundle storage bundle = bundles[bundleId];
        require(bundle.status == 3, "Not partial");
        require(msg.sender == bundle.initiator, "Not initiator");

        // BUG: This is a best-effort rollback — no guarantee it works
        // Operations on other chains may have been finalized
        // VULN #9: "Rollback" is just sending inverse transactions — not atomic either
        for (uint256 i = 0; i < bundle.executedCount; i++) {
            address bridge = chainBridges[bundle.chainIds[i]];
            // BUG: rollbackData not defined — this is a stub
            // In reality, can't roll back finalized cross-chain state
            (bool ok, ) = bridge.call(
                abi.encodeWithSignature("rollback(bytes)", bundle.callDatas[i])
            );
            // BUG: Ignores rollback failure — state remains inconsistent
            if (!ok) {
                emit BundleFailed(bundleId, i);
            }
        }

        bundle.status = 4; // failed
    }

    // ========== DOUBLE SPEND WINDOW ==========

    /// @notice Fast-path spend using preconfirmation
    // VULN #3: If L1 reorgs, preconf is invalidated but L2 state persists
    function preconfSpend(
        bytes32 preconfHash,
        address recipient,
        uint256 amount
    ) external {
        // BUG: No verification that preconf is still valid
        // VULN #3: L1 reorg window allows double-spend:
        //   1. Get preconf on L2-A (spend funds)
        //   2. L1 reorgs, preconf invalidated
        //   3. Funds are "back" on L1 — spent on L2-A AND available on L1

        // BUG: Direct transfer based on preconf alone
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    /// @notice Set chain bridge addresses
    function setChainBridge(uint256 chainId, address bridge) external {
        // BUG: No access control — anyone can change bridge addresses
        chainBridges[chainId] = bridge;
    }

    receive() external payable {}
}
