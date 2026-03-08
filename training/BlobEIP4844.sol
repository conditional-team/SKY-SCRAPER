// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BlobEIP4844
 * @dev Training Contract #60 - EIP-4844 Blob Fee Market & Data Availability Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Blob Fee Market Manipulation (BLOB-FEEMARKET-01)
 * 2. KZG Commitment Mismatch (BLOB-KZG-01)
 * 3. Data Availability Sampling Failure (BLOB-DASAMPLE-01)
 * 4. Blobspace Denial of Service (BLOB-DOS-01)
 * 5. L2 Sequencer Blob Cost Passthrough (BLOB-L2COST-01)
 * 6. Blob Gas Price Spike (BLOB-GASSPIKE-01)
 * 7. Proto-Danksharding Commitment Reuse (BLOB-COMMITREUSE-01)
 * 8. Blob Data Expiry Attack (BLOB-EXPIRY-01)
 * 9. Multi-Blob Transaction Atomicity (BLOB-ATOMICITY-01)
 * 10. Rollup Proof Window vs Blob TTL (BLOB-PROOFTTL-01)
 * 11. Excess Blob Gas Manipulation (BLOB-EXCESSGAS-01)
 * 12. Blob Precompile Input Validation (BLOB-PRECOMPILE-01)
 * 13. Type-3 Transaction Parsing (BLOB-TYPE3-01)
 * 14. Versioned Hash Collision (BLOB-VHASH-01)
 * 15. Blob Sidecar Censorship (BLOB-CENSOR-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): BLOB-*, EIP-4844, blob, KZG, danksharding
 * - Engine 2 (deep-semantic): data availability, fee market dynamics
 * - Engine 13 (mev-analyzer): blob fee gaming, sequencer extraction
 * - Engine 3 (state-desync): L2/L1 commitment desync
 */

contract BlobFeeMarket {

    struct BlobSubmission {
        bytes32 versionedHash;
        bytes32 kzgCommitment;
        uint256 blobGasPrice;
        uint256 timestamp;
        address submitter;
        bool verified;
    }

    struct L2BatchCommitment {
        bytes32 stateRoot;
        bytes32[] blobHashes;
        uint256 blobGasUsed;
        uint256 submissionBlock;
        uint256 proofDeadline;
        bool proven;
        bool finalized;
    }

    mapping(bytes32 => BlobSubmission) public blobSubmissions;
    mapping(uint256 => L2BatchCommitment) public l2Batches;
    uint256 public nextBatchId;

    // EIP-4844 parameters
    uint256 public constant TARGET_BLOB_GAS_PER_BLOCK = 393216; // 3 blobs
    uint256 public constant MAX_BLOB_GAS_PER_BLOCK = 786432;    // 6 blobs
    uint256 public constant BLOB_GASPRICE_UPDATE_FRACTION = 3338477;
    uint256 public constant MIN_BLOB_GASPRICE = 1; // 1 wei

    uint256 public excessBlobGas;
    uint256 public currentBlobGasPrice;
    
    mapping(address => uint256) public sequencerBlobBudget;
    address public owner;
    uint256 public constant PROOF_WINDOW = 7 days;
    uint256 public constant BLOB_TTL = 18 days; // ~4096 epochs

    constructor() {
        owner = msg.sender;
        currentBlobGasPrice = MIN_BLOB_GASPRICE;
    }

    // ========== VULN 1: Blob Fee Market Manipulation (BLOB-FEEMARKET-01) ==========

    // BUG #1: blob gas price can be pumped by filling blobspace
    function submitBlob(bytes32 versionedHash, bytes32 kzgCommitment) external payable {
        uint256 blobGas = 131072; // per-blob gas
        uint256 cost = blobGas * currentBlobGasPrice;
        require(msg.value >= cost, "insufficient fee");
        
        // VULN: attacker fills all 6 blob slots per block
        // blob gas price exponentially increases (EIP-1559 style)
        // other rollups can't afford blobs → forced to use calldata
        blobSubmissions[versionedHash] = BlobSubmission({
            versionedHash: versionedHash,
            kzgCommitment: kzgCommitment,
            blobGasPrice: currentBlobGasPrice,
            timestamp: block.timestamp,
            submitter: msg.sender,
            verified: false
        });
        
        _updateBlobGasPrice(blobGas);
    }

    // ========== VULN 2: KZG Commitment Mismatch (BLOB-KZG-01) ==========

    // BUG #2: KZG commitment verification not enforced on-chain
    function verifyBlobCommitment(
        bytes32 versionedHash,
        bytes32 kzgCommitment,
        bytes calldata proof
    ) external returns (bool) {
        // VULN: actual KZG verification requires point evaluation precompile (0x0a)
        // but this just stores the claim without calling the precompile
        // anyone can submit fake commitment → garbage blob accepted
        blobSubmissions[versionedHash].verified = true;
        blobSubmissions[versionedHash].kzgCommitment = kzgCommitment;
        // Should call: address(0x0a).staticcall(abi.encode(...))
        return true;
    }

    // ========== VULN 3: Data Availability Sampling Failure (BLOB-DASAMPLE-01) ==========

    mapping(bytes32 => bool) public availabilityAttested;

    // BUG #3: DA sampling relies on honest majority of attesters
    function attestDataAvailability(bytes32 blobHash, bool available) external {
        // VULN: no stake-weighted voting, any address can attest
        // colluding validators attest "available" for data they never downloaded
        if (available) {
            availabilityAttested[blobHash] = true;
        }
    }

    // ========== VULN 4: Blobspace Denial of Service (BLOB-DOS-01) ==========

    // BUG #4: max 6 blobs per block creates contention
    mapping(address => uint256) public blobReservations;
    uint256 public blobsThisBlock;

    function reserveBlobSlot() external payable {
        require(blobsThisBlock < 6, "block full");
        // VULN: attacker reserves all 6 slots per block at minimum price
        // legitimate rollups get crowded out
        // cost: 6 * 131072 * 1 wei = ~786K wei (near-zero cost to grief)
        blobsThisBlock++;
        blobReservations[msg.sender]++;
    }

    function resetBlock() external {
        require(msg.sender == owner);
        blobsThisBlock = 0;
    }

    // ========== VULN 5: L2 Sequencer Blob Cost Passthrough (BLOB-L2COST-01) ==========

    // BUG #5: L2 sequencer passes blob costs to users without proper accounting
    function estimateL2BlobCost(uint256 dataSize) external view returns (uint256) {
        uint256 blobsNeeded = (dataSize + 131072 - 1) / 131072;
        // VULN: uses stale currentBlobGasPrice
        // actual blob gas price at inclusion time may be 10x higher
        // sequencer charges users low estimate, absorbs loss or charges post-facto
        return blobsNeeded * 131072 * currentBlobGasPrice;
    }

    // ========== VULN 6: Blob Gas Price Spike (BLOB-GASSPIKE-01) ==========

    // BUG #6: exponential blob gas pricing can spike 100x in minutes
    function _updateBlobGasPrice(uint256 blobGasUsed) internal {
        if (blobGasUsed > TARGET_BLOB_GAS_PER_BLOCK) {
            excessBlobGas += blobGasUsed - TARGET_BLOB_GAS_PER_BLOCK;
        } else if (excessBlobGas > TARGET_BLOB_GAS_PER_BLOCK - blobGasUsed) {
            excessBlobGas -= TARGET_BLOB_GAS_PER_BLOCK - blobGasUsed;
        } else {
            excessBlobGas = 0;
        }
        // VULN: exponential pricing formula
        // 10 consecutive full blocks → price increases ~12x
        // rollups budgeting at current price face unexpected 10x costs
        currentBlobGasPrice = _fakeExponential(MIN_BLOB_GASPRICE, excessBlobGas, BLOB_GASPRICE_UPDATE_FRACTION);
    }

    function _fakeExponential(uint256 factor, uint256 numerator, uint256 denominator) 
        internal pure returns (uint256) 
    {
        uint256 output = 0;
        uint256 numerator_accum = factor * denominator;
        for (uint256 i = 1; numerator_accum > 0; i++) {
            output += numerator_accum;
            numerator_accum = (numerator_accum * numerator) / (denominator * i);
        }
        return output / denominator;
    }

    // ========== VULN 7: Proto-Danksharding Commitment Reuse (BLOB-COMMITREUSE-01) ==========

    mapping(bytes32 => uint256) public commitmentUseCount;

    // BUG #7: same KZG commitment reused across multiple submissions
    function submitWithCommitment(bytes32 commitment, bytes32 blobHash) external {
        // VULN: no uniqueness check on commitment
        // attacker reuses known-good commitment with different blob data
        commitmentUseCount[commitment]++;
        blobSubmissions[blobHash].kzgCommitment = commitment;
    }

    // ========== VULN 8: Blob Data Expiry Attack (BLOB-EXPIRY-01) ==========

    // BUG #8: blob data pruned after ~18 days
    function challengeBatch(uint256 batchId) external {
        L2BatchCommitment storage batch = l2Batches[batchId];
        require(!batch.finalized, "already final");
        
        // VULN: if challenge comes after blob data expired from beacon chain,
        // data to generate fraud proof is no longer available
        // batch auto-finalizes even if it was fraudulent
        for (uint256 i = 0; i < batch.blobHashes.length; i++) {
            // Can't reconstruct data from expired blob
            require(blobSubmissions[batch.blobHashes[i]].timestamp + BLOB_TTL > block.timestamp,
                "blob expired");
        }
    }

    // ========== VULN 9: Multi-Blob Transaction Atomicity (BLOB-ATOMICITY-01) ==========

    // BUG #9: L2 batch needs multiple blobs but they're not guaranteed atomic
    function submitBatchMultiBlob(
        bytes32 stateRoot,
        bytes32[] calldata blobHashes
    ) external returns (uint256 batchId) {
        // VULN: if 3 of 4 blobs make it into the block but 1 gets censored,
        // batch is incomplete but partially referenced
        // recovery logic doesn't handle partial submission
        batchId = nextBatchId++;
        l2Batches[batchId].stateRoot = stateRoot;
        l2Batches[batchId].submissionBlock = block.number;
        l2Batches[batchId].proofDeadline = block.timestamp + PROOF_WINDOW;
        for (uint256 i = 0; i < blobHashes.length; i++) {
            l2Batches[batchId].blobHashes.push(blobHashes[i]);
        }
        l2Batches[batchId].blobGasUsed = blobHashes.length * 131072;
    }

    // ========== VULN 10: Rollup Proof Window vs Blob TTL (BLOB-PROOFTTL-01) ==========

    // BUG #10: proof window longer than blob data availability
    function finalizeBatch(uint256 batchId) external {
        L2BatchCommitment storage batch = l2Batches[batchId];
        require(block.timestamp >= batch.proofDeadline, "proof window open");
        
        // VULN: PROOF_WINDOW = 7 days, BLOB_TTL = 18 days
        // But with extensions/disputes, effective window could exceed 18 days
        // after blob expiry, no one can verify the batch → auto-finalize fraud
        batch.finalized = true;
    }

    // ========== VULN 11: Excess Blob Gas Manipulation (BLOB-EXCESSGAS-01) ==========

    // BUG #11: excessBlobGas tracking can be manipulated across block boundaries
    function getEffectiveBlobGasPrice() external view returns (uint256) {
        // VULN: price is calculated from previous block's excess
        // multi-block attacker artificially inflates excess then benefits from spike
        return currentBlobGasPrice;
    }

    // ========== VULN 12: Blob Precompile Input Validation (BLOB-PRECOMPILE-01) ==========

    // BUG #12: point evaluation precompile (0x0a) input format validation
    function callPointEvaluation(
        bytes32 versionedHash,
        bytes32 z,
        bytes32 y,
        bytes calldata commitment,
        bytes calldata proof
    ) external view returns (bool) {
        // VULN: incorrect input packing for the precompile
        // versionedHash must be 0x01 prefixed, wrong version byte → fail
        (bool ok, ) = address(0x0a).staticcall(
            abi.encodePacked(versionedHash, z, y, commitment, proof)
        );
        // Some callers don't check return value
        return ok;
    }

    // ========== VULN 13: Type-3 Transaction Parsing (BLOB-TYPE3-01) ==========

    // BUG #13: Type 3 transaction has different encoding than Type 2
    // Contracts reading tx data may misparse
    function parseTxType() external view returns (uint8) {
        // VULN: msg.data for Type 3 tx includes blob_versioned_hashes
        // but internal contract calls don't have access to blob data
        // tx.type check not available in Solidity
        return 0; // Can't distinguish between tx types in contract
    }

    // ========== VULN 14: Versioned Hash Collision (BLOB-VHASH-01) ==========

    // BUG #14: versioned hash uses SHA256 truncated to 31 bytes + 1 byte version
    function registerVersionedHash(bytes32 vHash) external {
        require(uint8(vHash[0]) == 0x01, "invalid version");
        // VULN: 31-byte hash space → collision resistance reduced from 256 to 248 bits
        // In practice still safe, but combined with weak KZG setup, could be exploited
        blobSubmissions[vHash].submitter = msg.sender;
        blobSubmissions[vHash].timestamp = block.timestamp;
    }

    // ========== VULN 15: Blob Sidecar Censorship (BLOB-CENSOR-01) ==========

    mapping(address => uint256) public lastBlobSubmission;

    // BUG #15: blob sidecar can be censored by builders/proposers
    function monitorBlobInclusion(address rollup) external view returns (bool delayed) {
        // VULN: no forced inclusion mechanism for blobs
        // builder can censor specific rollup's blobs indefinitely
        // rollup forced to fallback to expensive calldata
        return block.timestamp - lastBlobSubmission[rollup] > 1 hours;
    }

    // ========== Admin ==========

    function setSequencerBudget(address sequencer, uint256 budget) external {
        require(msg.sender == owner);
        sequencerBlobBudget[sequencer] = budget;
    }

    receive() external payable {}
}
