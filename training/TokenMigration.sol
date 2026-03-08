// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TokenMigration
 * @dev Training Contract #64 - Token Migration & Swap Vulnerabilities
 *
 * VULNERABILITY CATEGORIES:
 * 1. Double Claim Migration (MIGRATE-DOUBLECLAIM-01)
 * 2. Snapshot Timing Attack (MIGRATE-SNAPSHOT-01)
 * 3. Merkle Proof Replay (MIGRATE-MERKLE-01)
 * 4. Migration Rate Manipulation (MIGRATE-RATE-01)
 * 5. Leftover Token Drain (MIGRATE-LEFTOVER-01)
 * 6. V1 Token Still Functional (MIGRATE-V1ACTIVE-01)
 * 7. Bridge Migration Desync (MIGRATE-BRIDGE-01)
 * 8. Airdrop Sybil Farming (MIGRATE-SYBIL-01)
 * 9. Vesting Schedule Reset (MIGRATE-VESTING-01)
 * 10. Migration Deadline Bypass (MIGRATE-DEADLINE-01)
 * 11. Cross-Chain Migration Race (MIGRATE-XCHAIN-01)
 * 12. Supply Mismatch (MIGRATE-SUPPLY-01)
 * 13. Governance Power During Migration (MIGRATE-GOVPOWER-01)
 * 14. Fee-on-Transfer Migration (MIGRATE-FEETRANSFER-01)
 * 15. Permit Signature Migration (MIGRATE-PERMITSIG-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): MIGRATE-*, migration, airdrop, merkle, snapshot
 * - Engine 2 (deep-semantic): claim logic, supply accounting, vesting
 * - Engine 3 (state-desync): snapshot vs live balance, cross-chain desync
 * - Engine 13 (mev-analyzer): front-running snapshot, sybil farming
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function burn(uint256 amount) external;
}

contract TokenMigrationHub {

    struct MigrationConfig {
        address v1Token;
        address v2Token;
        uint256 migrationRate; // v2 per v1, scaled by 1e18
        uint256 deadline;
        bytes32 merkleRoot;
        uint256 totalMigrated;
        uint256 maxSupplyV2;
        bool paused;
    }

    struct VestingSchedule {
        uint256 totalAmount;
        uint256 claimed;
        uint256 startTime;
        uint256 cliffDuration;
        uint256 vestingDuration;
    }

    MigrationConfig public config;
    mapping(address => bool) public hasMigrated;
    mapping(address => uint256) public migratedAmount;
    mapping(address => VestingSchedule) public vestingSchedules;
    mapping(bytes32 => bool) public usedProofs;
    
    address public owner;
    uint256 public snapshotBlock;
    mapping(address => uint256) public snapshotBalance;
    
    // Cross-chain
    mapping(uint256 => mapping(address => bool)) public chainMigrated;

    constructor(
        address _v1, address _v2, uint256 _rate, uint256 _deadline, bytes32 _root
    ) {
        owner = msg.sender;
        config = MigrationConfig({
            v1Token: _v1,
            v2Token: _v2,
            migrationRate: _rate,
            deadline: _deadline,
            merkleRoot: _root,
            totalMigrated: 0,
            maxSupplyV2: 100_000_000 * 1e18,
            paused: false
        });
    }

    // ========== VULN 1: Double Claim Migration (MIGRATE-DOUBLECLAIM-01) ==========

    // BUG #1: claim flag checked per address but tokens transferable between claims
    function migrate(uint256 amount) external {
        require(!config.paused, "paused");
        require(block.timestamp <= config.deadline, "expired");
        
        IERC20(config.v1Token).transferFrom(msg.sender, address(this), amount);
        uint256 v2Amount = amount * config.migrationRate / 1e18;
        
        // VULN: hasMigrated flag not set, only migratedAmount tracked
        // user migrates, gets V2, buys more V1 on DEX, migrates again
        migratedAmount[msg.sender] += v2Amount;
        config.totalMigrated += v2Amount;
        
        IERC20(config.v2Token).transfer(msg.sender, v2Amount);
    }

    // ========== VULN 2: Snapshot Timing Attack (MIGRATE-SNAPSHOT-01) ==========

    // BUG #2: snapshot block announced in advance
    function takeSnapshot() external {
        require(msg.sender == owner, "not owner");
        snapshotBlock = block.number;
        // VULN: if snapshot block is known, users can borrow/flash-loan tokens
        // to inflate their balance at snapshot time
    }

    function recordSnapshot(address user, uint256 balance) external {
        require(msg.sender == owner, "not owner");
        // VULN: off-chain snapshot recorded to on-chain mapping
        // centralised process, owner can set arbitrary balances
        snapshotBalance[user] = balance;
    }

    // ========== VULN 3: Merkle Proof Replay (MIGRATE-MERKLE-01) ==========

    // BUG #3: merkle proof doesn't include nonce or claim count
    function claimWithProof(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external {
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        
        // VULN: usedProofs tracks the leaf hash
        // but if same user has multiple leaves (different index), can claim multiple times
        // Also: proof valid on any chain where contract is deployed with same root
        require(!usedProofs[node], "already claimed");
        require(_verifyMerkle(merkleProof, config.merkleRoot, node), "invalid proof");
        
        usedProofs[node] = true;
        IERC20(config.v2Token).transfer(account, amount);
    }

    // ========== VULN 4: Migration Rate Manipulation (MIGRATE-RATE-01) ==========

    // BUG #4: owner can change migration rate mid-migration
    function setMigrationRate(uint256 newRate) external {
        require(msg.sender == owner, "not owner");
        // VULN: no time-lock, insider can change rate before migrating own tokens
        // set high rate → migrate own tokens → set rate back
        config.migrationRate = newRate;
    }

    // ========== VULN 5: Leftover Token Drain (MIGRATE-LEFTOVER-01) ==========

    // BUG #5: rescue function for unmigrated V2 tokens
    function rescueTokens(address token, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        // VULN: owner can drain V2 reserve before migration completes
        // also drains V1 tokens that were burned-by-migration
        IERC20(token).transfer(owner, amount);
    }

    // ========== VULN 6: V1 Token Still Functional (MIGRATE-V1ACTIVE-01) ==========

    // BUG #6: V1 token not paused/burned after migration
    function checkV1Status() external view returns (bool active, uint256 supply) {
        // VULN: V1 token still tradeable on DEXes after migration
        // users can buy cheap V1 and migrate to V2
        // no V1 pause mechanism
        supply = IERC20(config.v1Token).totalSupply();
        active = supply > 0;
    }

    // ========== VULN 7: Bridge Migration Desync (MIGRATE-BRIDGE-01) ==========

    mapping(uint256 => uint256) public chainMigrationCaps;

    // BUG #7: cross-chain migration with independent caps
    function migrateFromBridge(
        uint256 sourceChain,
        address user,
        uint256 amount,
        bytes calldata bridgeProof
    ) external {
        // VULN: no verification of bridgeProof
        // attacker claims migration on both chains
        require(!chainMigrated[sourceChain][user], "already migrated on this chain");
        chainMigrated[sourceChain][user] = true;
        
        uint256 v2Amount = amount * config.migrationRate / 1e18;
        IERC20(config.v2Token).transfer(user, v2Amount);
    }

    // ========== VULN 8: Airdrop Sybil Farming (MIGRATE-SYBIL-01) ==========

    mapping(address => bool) public airdropClaimed;
    uint256 public airdropPerUser = 1000 * 1e18;

    // BUG #8: flat airdrop per address, sybil-attackable
    function claimAirdrop() external {
        require(!airdropClaimed[msg.sender], "claimed");
        airdropClaimed[msg.sender] = true;
        // VULN: 1000 tokens per address, attacker creates 10000 addresses
        // costs only gas, gets 10M tokens
        IERC20(config.v2Token).transfer(msg.sender, airdropPerUser);
    }

    // ========== VULN 9: Vesting Schedule Reset (MIGRATE-VESTING-01) ==========

    // BUG #9: migrating tokens resets vesting schedule
    function migrateWithVesting(uint256 amount) external {
        IERC20(config.v1Token).transferFrom(msg.sender, address(this), amount);
        uint256 v2Amount = amount * config.migrationRate / 1e18;
        
        // VULN: creates new vesting schedule, doesn't honor V1 vesting progress
        // user was 80% vested in V1, gets reset to 0% in V2
        vestingSchedules[msg.sender] = VestingSchedule({
            totalAmount: v2Amount,
            claimed: 0,
            startTime: block.timestamp,
            cliffDuration: 180 days,
            vestingDuration: 730 days
        });
    }

    // ========== VULN 10: Migration Deadline Bypass (MIGRATE-DEADLINE-01) ==========

    // BUG #10: deadline extendable by owner
    function extendDeadline(uint256 newDeadline) external {
        require(msg.sender == owner, "not owner");
        // VULN: can extend deadline indefinitely
        // keeps migration window open → price uncertainty for V2
        config.deadline = newDeadline;
    }

    // ========== VULN 11: Cross-Chain Migration Race (MIGRATE-XCHAIN-01) ==========

    // BUG #11: Same user migrates same tokens on two chains simultaneously
    function migrateWithChainVerification(uint256 amount, uint256 chainId) external {
        require(chainId == block.chainid, "wrong chain");
        // VULN: chainId check is local, doesn't prevent same migration on other chain
        // bridge latency means both chains accept before either knows about the other
        migratedAmount[msg.sender] += amount;
        uint256 v2Amount = amount * config.migrationRate / 1e18;
        IERC20(config.v2Token).transfer(msg.sender, v2Amount);
    }

    // ========== VULN 12: Supply Mismatch (MIGRATE-SUPPLY-01) ==========

    // BUG #12: V2 supply can exceed max if migration + airdrop combined
    function checkSupplyInvariant() external view returns (bool valid) {
        uint256 v2Supply = IERC20(config.v2Token).totalSupply();
        // VULN: total migrated + airdrops + vesting can exceed maxSupplyV2
        // no global supply check on mint
        return v2Supply <= config.maxSupplyV2;
    }

    // ========== VULN 13: Governance Power During Migration (MIGRATE-GOVPOWER-01) ==========

    // BUG #13: V1 holder has governance power AND gets V2 governance power
    mapping(address => uint256) public governanceVotes;

    function delegateVotes(address delegatee) external {
        // VULN: user holds V1 governance + migrates partial → gets V2 governance
        // voting power = V1 balance + V2 balance during transition
        uint256 v1Balance = IERC20(config.v1Token).balanceOf(msg.sender);
        uint256 v2Balance = IERC20(config.v2Token).balanceOf(msg.sender);
        governanceVotes[delegatee] += v1Balance + v2Balance;
    }

    // ========== VULN 14: Fee-on-Transfer Migration (MIGRATE-FEETRANSFER-01) ==========

    // BUG #14: V1 token has transfer fee, less arrives than expected
    function migrateExact(uint256 expectedAmount) external {
        uint256 balBefore = IERC20(config.v1Token).balanceOf(address(this));
        IERC20(config.v1Token).transferFrom(msg.sender, address(this), expectedAmount);
        uint256 balAfter = IERC20(config.v1Token).balanceOf(address(this));
        
        // VULN: if V1 has transfer fee, balAfter - balBefore < expectedAmount
        // but V2 minted based on expectedAmount, not actual received
        uint256 v2Amount = expectedAmount * config.migrationRate / 1e18;
        // Should use (balAfter - balBefore) instead of expectedAmount
        IERC20(config.v2Token).transfer(msg.sender, v2Amount);
    }

    // ========== VULN 15: Permit Signature Migration (MIGRATE-PERMITSIG-01) ==========

    // BUG #15: V1 permits still valid but V2 uses different nonce space
    function migrateWithPermit(
        uint256 amount, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        // VULN: permit was signed for V1 domain separator
        // if V2 has same name/version and deployed at same address, sig replays
        // Also: V1 permit still valid after migration → allowance persists
        (bool ok, ) = config.v1Token.call(
            abi.encodeWithSignature(
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                msg.sender, address(this), amount, deadline, v, r, s
            )
        );
        require(ok, "permit failed");
        
        IERC20(config.v1Token).transferFrom(msg.sender, address(this), amount);
        IERC20(config.v2Token).transfer(msg.sender, amount * config.migrationRate / 1e18);
    }

    // ========== Helpers ==========

    function _verifyMerkle(
        bytes32[] calldata proof, bytes32 root, bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 hash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (hash <= proof[i]) {
                hash = keccak256(abi.encodePacked(hash, proof[i]));
            } else {
                hash = keccak256(abi.encodePacked(proof[i], hash));
            }
        }
        return hash == root;
    }

    function claimVested() external {
        VestingSchedule storage vs = vestingSchedules[msg.sender];
        require(block.timestamp >= vs.startTime + vs.cliffDuration, "cliff");
        uint256 elapsed = block.timestamp - vs.startTime;
        if (elapsed > vs.vestingDuration) elapsed = vs.vestingDuration;
        uint256 vested = vs.totalAmount * elapsed / vs.vestingDuration;
        uint256 claimable = vested - vs.claimed;
        vs.claimed += claimable;
        IERC20(config.v2Token).transfer(msg.sender, claimable);
    }
}
