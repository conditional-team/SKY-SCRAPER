// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZKCoprocessor
 * @dev Training Contract #66 - ZK Coprocessor & Proof Verification Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Proof Verification Bypass (ZK-PROOFBYPASS-01)
 * 2. Public Input Manipulation (ZK-PUBINPUT-01)
 * 3. Verifier Key Rotation Gap (ZK-KEYROTATION-01)
 * 4. Groth16 Malleability (ZK-GROTH16MAL-01)
 * 5. Trusted Setup Compromise (ZK-TRUSTEDSETUP-01)
 * 6. SNARK-Unfriendly Hash Exploit (ZK-HASHEXPLOIT-01)
 * 7. Proof Replay Across Instances (ZK-PROOFREPLAY-01)
 * 8. Recursive Proof Depth Limit (ZK-RECDEPTH-01)
 * 9. Witness Extraction Attack (ZK-WITNESS-01)
 * 10. Aggregated Proof Splitting (ZK-AGGSPLIT-01)
 * 11. Coprocessor Result Trust (ZK-COPTRUST-01)
 * 12. Verification Gas DoS (ZK-GASDOS-01)
 * 13. Fiat-Shamir Weakness (ZK-FIATSHAMIR-01)
 * 14. Null Proof Acceptance (ZK-NULLPROOF-01)
 * 15. Verifier Contract Upgrade (ZK-VERUPGRADE-01)
 * 16. Batch Proof One-Bad-Apple (ZK-BATCHBAD-01)
 * 17. Prover Censorship (ZK-PROVERCENSOR-01)
 * 18. Off-Chain Compute Mismatch (ZK-OFFCHAIN-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): ZK-*, proof, verifier, SNARK, groth16, coprocessor
 * - Engine 2 (deep-semantic): verification logic, trust assumptions
 * - Engine 20 (bytecode-flow): verifier bytecode anomalies
 * - Engine 5 (compiler-vulns): precompile interaction edge cases
 */

interface IVerifier {
    function verify(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}

contract ZKCoprocessorProtocol {

    struct ProofSubmission {
        bytes32 proofHash;
        uint256[] publicInputs;
        address prover;
        uint256 submittedBlock;
        bool verified;
        bool challenged;
    }

    struct VerifierConfig {
        address verifierContract;
        bytes32 verificationKey;
        uint256 deployedBlock;
        bool active;
    }

    mapping(uint256 => ProofSubmission) public submissions;
    uint256 public nextSubmissionId;
    mapping(bytes32 => bool) public usedProofHashes;
    
    VerifierConfig public currentVerifier;
    VerifierConfig[] public verifierHistory;
    
    mapping(address => bool) public authorizedProvers;
    address public owner;
    
    uint256 public proofReward = 0.1 ether;
    uint256 public challengeWindow = 1 hours;
    
    // Coprocessor results
    mapping(bytes32 => uint256) public computeResults;
    mapping(bytes32 => bool) public resultFinalized;

    constructor(address _verifier, bytes32 _vk) {
        owner = msg.sender;
        currentVerifier = VerifierConfig({
            verifierContract: _verifier,
            verificationKey: _vk,
            deployedBlock: block.number,
            active: true
        });
    }

    // ========== VULN 1: Proof Verification Bypass (ZK-PROOFBYPASS-01) ==========

    // BUG #1: verification call result not checked
    function submitProof(bytes calldata proof, uint256[] calldata publicInputs) 
        external returns (uint256 id) 
    {
        id = nextSubmissionId++;
        
        // VULN: calls verifier but doesn't revert on false
        (bool ok, bytes memory ret) = currentVerifier.verifierContract.staticcall(
            abi.encodeWithSelector(IVerifier.verify.selector, proof, publicInputs)
        );
        // ok is true if call didn't revert, but return value may be false
        // No check on decoded return value!
        
        submissions[id] = ProofSubmission({
            proofHash: keccak256(proof),
            publicInputs: publicInputs,
            prover: msg.sender,
            submittedBlock: block.number,
            verified: ok, // BUG: should be: ok && abi.decode(ret, (bool))
            challenged: false
        });
    }

    // ========== VULN 2: Public Input Manipulation (ZK-PUBINPUT-01) ==========

    // BUG #2: public inputs not validated against expected format
    function submitWithResult(
        bytes calldata proof, 
        uint256[] calldata publicInputs,
        bytes32 resultHash
    ) external {
        // VULN: publicInputs[0] should be the result hash
        // but nothing validates publicInputs[0] == resultHash
        // prover submits valid proof for different result, claims it matches
        require(IVerifier(currentVerifier.verifierContract).verify(proof, publicInputs), "invalid");
        
        computeResults[resultHash] = publicInputs.length > 1 ? publicInputs[1] : 0;
        resultFinalized[resultHash] = true;
    }

    // ========== VULN 3: Verifier Key Rotation Gap (ZK-KEYROTATION-01) ==========

    // BUG #3: new verification key, old proofs still verifiable with old key
    function rotateVerifier(address newVerifier, bytes32 newVk) external {
        require(msg.sender == owner, "not owner");
        // VULN: no invalidation of proofs generated with old key
        // submissions verified against old verifier are still marked valid
        verifierHistory.push(currentVerifier);
        currentVerifier = VerifierConfig({
            verifierContract: newVerifier,
            verificationKey: newVk,
            deployedBlock: block.number,
            active: true
        });
    }

    // ========== VULN 4: Groth16 Malleability (ZK-GROTH16MAL-01) ==========

    // BUG #4: Groth16 proofs are malleable — same witness, different proof bytes
    function submitUniqueProof(bytes calldata proof, uint256[] calldata publicInputs) external {
        bytes32 proofHash = keccak256(proof);
        require(!usedProofHashes[proofHash], "proof already used");
        
        // VULN: Groth16 proof (A, B, C) can be transformed:
        // A' = -A, B' = -B produces different bytes but same verification result
        // attacker submits malleable variant → "new" proof for same computation
        usedProofHashes[proofHash] = true;
        
        require(IVerifier(currentVerifier.verifierContract).verify(proof, publicInputs), "invalid");
    }

    // ========== VULN 5: Trusted Setup Compromise (ZK-TRUSTEDSETUP-01) ==========

    bytes32 public trustedSetupHash;

    // BUG #5: trusted setup parameters stored as hash, not verified on-chain
    function setTrustedSetup(bytes32 setupHash) external {
        require(msg.sender == owner, "not owner");
        // VULN: if toxic waste from ceremony not destroyed,
        // anyone with it can forge proofs for any statement
        // contract has no way to detect compromised setup
        trustedSetupHash = setupHash;
    }

    // ========== VULN 6: SNARK-Unfriendly Hash Exploit (ZK-HASHEXPLOIT-01) ==========

    // BUG #6: keccak256 is SNARK-unfriendly, Poseidon expected
    function verifyComputation(bytes32 inputHash, uint256 result) external view returns (bool) {
        // VULN: hashing inside ZK circuit uses Poseidon
        // but on-chain verification uses keccak256
        // if hashes don't match, valid proofs may fail verification
        bytes32 onChainHash = keccak256(abi.encode(result));
        return onChainHash == inputHash;
        // Poseidon(result) ≠ keccak256(abi.encode(result))
    }

    // ========== VULN 7: Proof Replay Across Instances (ZK-PROOFREPLAY-01) ==========

    // BUG #7: proof valid for this contract also valid on another deployment
    function verifyWithInstance(
        bytes calldata proof, 
        uint256[] calldata publicInputs,
        address instance
    ) external view returns (bool) {
        // VULN: no instance-specific binding in the proof
        // same proof + public inputs work on any contract with same verifier
        return IVerifier(currentVerifier.verifierContract).verify(proof, publicInputs);
    }

    // ========== VULN 8: Recursive Proof Depth Limit (ZK-RECDEPTH-01) ==========

    uint256 public maxRecursionDepth = 10;

    // BUG #8: recursive proof verification can exceed gas limits
    function verifyRecursiveProof(
        bytes[] calldata proofChain, 
        uint256[][] calldata inputChain
    ) external view returns (bool) {
        require(proofChain.length <= maxRecursionDepth, "too deep");
        // VULN: each verification costs ~300k gas
        // 10 recursive proofs = 3M gas, close to block limit in some scenarios
        // also: intermediate proof results not validated
        for (uint256 i = 0; i < proofChain.length; i++) {
            bool valid = IVerifier(currentVerifier.verifierContract).verify(
                proofChain[i], inputChain[i]
            );
            if (!valid) return false;
        }
        return true;
    }

    // ========== VULN 9: Witness Extraction Attack (ZK-WITNESS-01) ==========

    // BUG #9: proof allows extracting private witness data
    function submitPrivateComputation(
        bytes calldata proof,
        uint256 publicResult,
        bytes32 commitmentHash
    ) external {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = publicResult;
        inputs[1] = uint256(commitmentHash);
        require(IVerifier(currentVerifier.verifierContract).verify(proof, inputs), "invalid");
        
        // VULN: commitmentHash can be brute-forced if search space is small
        // e.g., proving "my balance > 1000" reveals approximate balance range
        // observer narrows private data from public proof parameters
        computeResults[commitmentHash] = publicResult;
    }

    // ========== VULN 10: Aggregated Proof Splitting (ZK-AGGSPLIT-01) ==========

    // BUG #10: batch aggregated proof claims multiple results
    function submitAggregatedProof(
        bytes calldata aggProof,
        bytes32[] calldata resultHashes,
        uint256[] calldata results
    ) external {
        require(resultHashes.length == results.length, "length mismatch");
        // VULN: aggregated proof verified once, but binding between
        // proof and individual results not checked
        // attacker substitutes one result in the batch
        uint256[] memory inputs = new uint256[](results.length);
        for (uint256 i = 0; i < results.length; i++) {
            inputs[i] = results[i];
        }
        require(IVerifier(currentVerifier.verifierContract).verify(aggProof, inputs), "invalid");
        
        for (uint256 i = 0; i < resultHashes.length; i++) {
            computeResults[resultHashes[i]] = results[i];
            resultFinalized[resultHashes[i]] = true;
        }
    }

    // ========== VULN 11: Coprocessor Result Trust (ZK-COPTRUST-01) ==========

    // BUG #11: coprocessor result used directly in state transition
    function applyCoprocessorResult(bytes32 taskId, uint256 result) external {
        require(resultFinalized[taskId], "not finalized");
        // VULN: result from coprocessor trusted without bounds checking
        // coprocessor returns uint256 max → overflow in consuming logic
        computeResults[taskId] = result;
        // Consuming contract does: balance += result (potential overflow)
    }

    // ========== VULN 12: Verification Gas DoS (ZK-GASDOS-01) ==========

    // BUG #12: complex proof requires more gas than block gas limit
    function verifyLargeProof(bytes calldata proof, uint256 numPublicInputs) external view returns (bool) {
        uint256[] memory inputs = new uint256[](numPublicInputs);
        // VULN: attacker submits proof with 10000 public inputs
        // verification gas = O(n) where n = public inputs
        // exceeds block gas limit → transaction always reverts
        for (uint256 i = 0; i < numPublicInputs; i++) {
            inputs[i] = i;
        }
        return IVerifier(currentVerifier.verifierContract).verify(proof, inputs);
    }

    // ========== VULN 13: Fiat-Shamir Weakness (ZK-FIATSHAMIR-01) ==========

    // BUG #13: weak Fiat-Shamir transform in custom verifier
    function customVerify(
        uint256 commitment, uint256 challenge, uint256 response
    ) external pure returns (bool) {
        // VULN: challenge should be hash of commitment + public inputs
        // but verifier doesn't recompute challenge → prover can choose convenient challenge
        // This breaks soundness of the interactive proof
        return (response == commitment + challenge); // Trivial to forge
    }

    // ========== VULN 14: Null Proof Acceptance (ZK-NULLPROOF-01) ==========

    // BUG #14: empty proof bytes accepted as valid
    function verifyProof(bytes calldata proof, uint256[] calldata inputs) external view returns (bool) {
        if (proof.length == 0) {
            // VULN: should reject empty proof
            // some verifiers return true for empty input
            return true;
        }
        return IVerifier(currentVerifier.verifierContract).verify(proof, inputs);
    }

    // ========== VULN 15: Verifier Contract Upgrade (ZK-VERUPGRADE-01) ==========

    // BUG #15: verifier contract is upgradeable proxy
    function upgradeVerifier(address newImpl) external {
        require(msg.sender == owner, "not owner");
        // VULN: upgrading verifier can change verification semantics
        // all pending proofs may become invalid or vice versa
        // malicious upgrade: new verifier returns true for everything
        currentVerifier.verifierContract = newImpl;
    }

    // ========== VULN 16: Batch Proof One-Bad-Apple (ZK-BATCHBAD-01) ==========

    // BUG #16: one invalid proof in batch invalidates all
    function verifyBatch(bytes[] calldata proofs, uint256[][] calldata inputs) 
        external view returns (bool) 
    {
        for (uint256 i = 0; i < proofs.length; i++) {
            // VULN: if any proof fails, entire batch rejected
            // attacker submits their own invalid proof into others' batch
            if (!IVerifier(currentVerifier.verifierContract).verify(proofs[i], inputs[i])) {
                return false;
            }
        }
        return true;
    }

    // ========== VULN 17: Prover Censorship (ZK-PROVERCENSOR-01) ==========

    // BUG #17: only authorized provers can submit
    function submitAuthorizedProof(bytes calldata proof, uint256[] calldata inputs) external {
        require(authorizedProvers[msg.sender], "not authorized");
        // VULN: if all authorized provers collude or go offline,
        // no proofs can be submitted → protocol halts
        // no fallback prover mechanism
        require(IVerifier(currentVerifier.verifierContract).verify(proof, inputs), "invalid");
    }

    // ========== VULN 18: Off-Chain Compute Mismatch (ZK-OFFCHAIN-01) ==========

    // BUG #18: off-chain coprocessor computes with different precision
    function storeOffchainResult(bytes32 taskId, uint256 offchainResult, uint256 onchainResult) external {
        // VULN: off-chain computation uses 256-bit field elements
        // on-chain uses uint256 with different modular arithmetic
        // results diverge for edge cases near field prime
        require(offchainResult == onchainResult, "mismatch");
        // This check passes for most cases but fails near 2^256
        computeResults[taskId] = onchainResult;
    }

    // ========== Admin ==========

    function authorizeProver(address prover) external {
        require(msg.sender == owner);
        authorizedProvers[prover] = true;
    }

    function setReward(uint256 reward) external {
        require(msg.sender == owner);
        proofReward = reward;
    }

    receive() external payable {}
}
