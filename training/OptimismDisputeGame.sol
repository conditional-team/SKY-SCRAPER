// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title OptimismDisputeGame
 * @dev Training Contract #68 - Optimism Fault Proof Dispute Game + Bond Logic (2025/2026)
 *
 * CUTTING EDGE VULNERABILITIES:
 * 1.  Dispute game clock manipulation (grandparent clock inheritance)
 * 2.  Invalid move acceptance without claim validation
 * 3.  Bond calculation overflow/underflow
 * 4.  Bond distribution accounting errors
 * 5.  Split depth boundary exploitation
 * 6.  Credit double-claim via reentrancy
 * 7.  Resolution race conditions
 * 8.  Preimage oracle manipulation
 * 9.  VM step witness forgery
 * 10. DelayedWETH unauthorized drain
 *
 * TARGETED PATTERNS (32):
 *   DISPUTE-01 through DISPUTE-16 (dispute-game crate)
 *   BOND-01 through BOND-16 (bond-logic crate)
 *
 * REAL-WORLD EXAMPLES:
 * - Optimism Fault Proof System (Cannon MIPS VM)
 * - Dispute Game Factory pattern (OP Stack)
 * - DelayedWETH bond escrow (OP Mainnet 2024-2025)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 17_L2SequencerExploit (sequencer state roots)
 * - Links to 19_BridgeOracleManipulation (bridge finality)
 * - Links to OptimismWithdrawalBridge (withdrawal proofs)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 25: Finality (challenge windows, finalization)
 * - Engine 4:  Temporal (clock manipulation, race conditions)
 * - Engine 17: Cross-Contract (L1-L2 interactions)
 * - Engine 7:  Economic (bond griefing, credit theft)
 */

// ========== LIBRARIES ==========

/// @dev Clock library for dispute game timing
library LibClock {
    function wrap(uint64 _duration, uint64 _timestamp) internal pure returns (uint128) {
        return uint128(_duration) << 64 | uint128(_timestamp);
    }

    function duration(uint128 _clock) internal pure returns (uint64) {
        return uint64(_clock >> 64);
    }

    function timestamp(uint128 _clock) internal pure returns (uint64) {
        return uint64(_clock);
    }
}

/// @dev Position library for game tree navigation
library LibPosition {
    function depth(uint128 _position) internal pure returns (uint8) {
        // BUG (implicit): depth extraction does not check MAX_GAME_DEPTH
        uint8 msb;
        uint128 x = _position;
        while (x > 0) { msb++; x >>= 1; }
        return msb;
    }

    function parent(uint128 _position) internal pure returns (uint128) {
        return _position >> 1;
    }

    function attack(uint128 _position) internal pure returns (uint128) {
        return _position * 2;
    }

    function defend(uint128 _position) internal pure returns (uint128) {
        return _position * 2 + 1;
    }
}

// ========== TYPES ==========

/// Claim type - a bytes32 state commitment
type Claim is bytes32;

/// Game status enum
enum GameStatus {
    IN_PROGRESS,
    CHALLENGER_WINS,
    DEFENDER_WINS
}

/// Clock duration type
type Duration is uint64;

// ========== INTERFACES ==========

/// @dev Preimage Oracle interface (Cannon VM)
interface IPreimageOracle {
    function readPreimage(bytes32 key, uint256 offset) external view returns (bytes32, uint256);
    function loadPreimage(bytes32 key, bytes calldata data) external;
}

/// @dev MIPS VM interface (Cannon single-step executor)
interface IMIPS {
    function step(bytes calldata stateData, bytes calldata proof) external returns (bytes32 postState);
}

/// @dev DelayedWETH interface for bond escrow
interface IDelayedWETH {
    function unlock(address guy, uint256 wad) external;
    function withdraw(address guy, uint256 wad) external;
    function deposit() external payable;
    function balanceOf(address) external view returns (uint256);
}

/// @dev Anchor State Registry
interface IAnchorStateRegistry {
    function anchors(uint32 gameType) external view returns (bytes32 root, uint256 l2BlockNumber);
}

/// @dev Dispute Game Factory
interface IDisputeGameFactory {
    function create(uint32 gameType, Claim rootClaim, bytes calldata extraData) external payable returns (address);
    function games(uint32 gameType, Claim rootClaim, bytes calldata extraData) external view returns (address, uint64);
}

// ========== MAIN CONTRACT ==========

contract OptimismDisputeGame {
    using LibClock for uint128;
    using LibPosition for uint128;

    // ========== CONSTANTS ==========

    // DISPUTE-07 / TIME-07: Challenge period — short enough to exploit
    uint256 public constant CHALLENGE_PERIOD = 3 days;

    // DISPUTE-10: Max game depth — reachable to force resolution
    uint256 public constant MAX_GAME_DEPTH = 73;

    // DISPUTE-09: Split depth — boundary between output bisection and execution
    uint256 public constant SPLIT_DEPTH = 30;

    // BOND-13: Minimum bond — griefing-low
    uint256 public constant MIN_BOND = 0.001 ether;

    // BOND-14: MAX_GAME_DEPTH allows excessive bond escalation
    // Combined with BOND-02: bond escalation by depth without bounds
    uint256 public constant BASE_BOND = 0.08 ether;

    // DISPUTE-01: Clock extension — can be bypassed
    uint64 public constant CLOCK_EXTENSION = 3 hours;
    uint64 public constant MAX_CLOCK_DURATION = 3.5 days;

    // TIME-08: Finalization period too short
    uint256 public constant FINALIZATION_PERIOD = 2 days;

    // BOND-12: Delay for WETH withdrawal
    uint256 public constant DELAY_SECONDS = 7 days;

    // ========== STATE ==========

    /// @dev Game status
    // DISPUTE-07 / TIME-14: Status change not atomic — race condition
    GameStatus public status;

    /// @dev Root claim (L2 output root)
    Claim public rootClaim;

    /// @dev Game creation timestamp
    uint256 public createdAt;

    /// @dev All claims in the game tree
    struct ClaimData {
        uint32 parentIndex;
        address counteredBy;
        address claimant;
        uint128 bond;
        Claim claim;
        uint128 position;
        uint128 clock;
    }

    /// @dev Claim data array
    ClaimData[] public claimData;

    /// @dev Resolved subgames
    // BOND-08: Can be resolved multiple times (missing check)
    mapping(uint256 => bool) public resolvedSubgames;

    /// @dev Credits owed to participants
    // BOND-07: Credit can be claimed multiple times
    // BOND-09: Credit accounting vulnerable to overflow
    mapping(address => uint256) public credit;

    /// @dev Preimage oracle
    IPreimageOracle public oracle;

    /// @dev MIPS VM
    IMIPS public vm;

    /// @dev DelayedWETH for bond escrow
    IDelayedWETH public weth;

    /// @dev Anchor state registry
    IAnchorStateRegistry public anchorStateRegistry;

    /// @dev Extra data (L2 block number for anchor)
    bytes public extraData;

    /// @dev Starting block number
    uint256 public startingBlockNumber;

    // ========== EVENTS ==========

    event Move(uint256 indexed parentIndex, Claim indexed claim, address indexed claimant);
    event Resolved(GameStatus indexed status);
    event CreditClaimed(address indexed recipient, uint256 amount);

    // ========== CONSTRUCTOR ==========

    constructor(
        Claim _rootClaim,
        bytes memory _extraData,
        address _weth,
        address _oracle,
        address _vm,
        address _anchorRegistry
    ) {
        // DISPUTE-15: rootClaim is NOT immutable — can be modified later
        rootClaim = _rootClaim;
        extraData = _extraData;
        createdAt = block.timestamp;
        status = GameStatus.IN_PROGRESS;

        weth = IDelayedWETH(_weth);
        oracle = IPreimageOracle(_oracle);
        vm = IMIPS(_vm);
        anchorStateRegistry = IAnchorStateRegistry(_anchorRegistry);

        // DISPUTE-16: Anchor state / extra data not validated
        // No check: extraData actually matches anchorStateRegistry
        // No check: startingBlockNumber is within valid range
        startingBlockNumber = abi.decode(_extraData, (uint256));

        // Initialize root claim as first claim
        claimData.push(ClaimData({
            parentIndex: type(uint32).max,
            counteredBy: address(0),
            claimant: msg.sender,
            bond: uint128(msg.value),
            claim: _rootClaim,
            position: 1,
            clock: LibClock.wrap(0, uint64(block.timestamp))
        }));
    }

    // ========== DISPUTE GAME MOVES ==========

    /**
     * @dev Attack a claim in the game tree
     *
     * DISPUTE-03: Move function lacks claim validation — no require(_claim) or assert(valid)
     * DISPUTE-05: Bond requirement can be bypassed — getRequiredBond called but NOT enforced
     * BOND-05:   Move accepts insufficient bond — msg.value not checked against required
     */
    function attack(uint256 _parentIndex, Claim _claim) external payable {
        // DISPUTE-14: parentIndex can point to wrong claim — no bounds check
        ClaimData storage parent = claimData[_parentIndex];

        // DISPUTE-01: Clock duration check can be bypassed
        // Only checks < not <=, and attacker can force timeout
        uint64 parentDuration = parent.clock.duration();
        if (parentDuration < MAX_CLOCK_DURATION) {
            // BUG: Clock check passes even when very close to MAX
        }

        // DISPUTE-02: Grandparent clock inheritance exploitable
        uint128 grandparentClock;
        if (parent.parentIndex != type(uint32).max) {
            grandparentClock = claimData[parent.parentIndex].clock;
            // BUG: getChallengerDuration uses grandparent clock without min check
        }

        uint128 nextPosition = parent.position.attack();

        // DISPUTE-10: nextPositionDepth can exceed MAX_GAME_DEPTH
        // BUG: No revert GameDepthExceeded — depth check missing
        uint8 nextPositionDepth = nextPosition.depth();

        // DISPUTE-09: Split depth boundary exploitation
        // BUG: SPLIT_DEPTH + 1 / SPLIT_DEPTH - 1 not properly handled
        if (nextPositionDepth == SPLIT_DEPTH + 1) {
            // Should transition from output bisection to execution bisection
            // BUG: No _verifyExecBisection call
        }

        // DISPUTE-05 / BOND-05: getRequiredBond is called but NOT enforced
        // BUG: No `require(msg.value >= getRequiredBond(nextPosition))`
        uint256 required = getRequiredBond(nextPosition);
        // Missing: revert IncorrectBondAmount();

        // DISPUTE-03: No claim validation whatsoever
        // BUG: _claim is not verified against parent state transition

        // TIME-11: Clock duration without minimum bound
        uint128 newClock = LibClock.wrap(
            parentDuration + uint64(block.timestamp - parent.clock.timestamp()),
            uint64(block.timestamp)
        );

        claimData.push(ClaimData({
            parentIndex: uint32(_parentIndex),
            counteredBy: address(0),
            claimant: msg.sender,
            bond: uint128(msg.value),
            claim: _claim,
            position: nextPosition,
            clock: newClock
        }));

        // Mark parent as countered
        parent.counteredBy = msg.sender;

        emit Move(_parentIndex, _claim, msg.sender);
    }

    /**
     * @dev Defend a claim in the game tree
     * Same bugs as attack() — shared move logic
     */
    function defend(uint256 _parentIndex, Claim _claim) external payable {
        ClaimData storage parent = claimData[_parentIndex];

        uint128 nextPosition = parent.position.defend();
        uint8 nextPositionDepth = nextPosition.depth();

        // DISPUTE-05 / BOND-05: Bond not enforced
        uint256 required = getRequiredBond(nextPosition);

        // DISPUTE-03: No claim validation
        // DISPUTE-10: No max depth check

        uint64 parentDuration = parent.clock.duration();
        uint128 newClock = LibClock.wrap(
            parentDuration + uint64(block.timestamp - parent.clock.timestamp()),
            uint64(block.timestamp)
        );

        claimData.push(ClaimData({
            parentIndex: uint32(_parentIndex),
            counteredBy: address(0),
            claimant: msg.sender,
            bond: uint128(msg.value),
            claim: _claim,
            position: nextPosition,
            clock: newClock
        }));

        parent.counteredBy = msg.sender;
        emit Move(_parentIndex, _claim, msg.sender);
    }

    /**
     * @dev Single-step VM execution for leaf claims
     *
     * DISPUTE-04: Execution bisection without proper VM step verification
     * DISPUTE-12: VM step can accept invalid witness
     */
    function step(
        uint256 _claimIndex,
        bool _isAttack,
        bytes calldata _stateData,
        bytes calldata _proof
    ) external {
        ClaimData storage claim = claimData[_claimIndex];

        // DISPUTE-11: Preimage oracle can be manipulated
        // BUG: loadPreimage called without checking keccak256(_stateData) == preState
        oracle.loadPreimage(Claim.unwrap(claim.claim), _stateData);

        // DISPUTE-04: Step without preimageOracle verification
        // DISPUTE-12: vm().step result NOT checked against postState
        // BUG: vm().step called but return value (postState) is ignored
        bytes32 postState = vm.step(_stateData, _proof);

        // BUG: No check: postState == expectedPostState
        // BUG: No check: parentPostAgree validation
        // Result is just silently accepted

        // Mark as countered regardless of VM step result
        if (_isAttack) {
            claimData[claimData[_claimIndex].parentIndex].counteredBy = msg.sender;
        }
    }

    // ========== BOND CALCULATION ==========

    /**
     * @dev Calculate required bond for a position
     *
     * BOND-01: Bond calculation may overflow
     * BOND-02: Bond escalation by depth without bounds
     * BOND-06: Bond at split depth can be bypassed
     */
    function getRequiredBond(uint128 _position) public view returns (uint256) {
        uint8 posDepth = _position.depth();

        // BOND-02: depth * BASE_BOND without bounds check
        // BOND-01: Can overflow for large depths
        uint256 bond = BASE_BOND * (2 ** posDepth);

        // BOND-06: Split depth special case — no extra requirement
        // BUG: At SPLIT_DEPTH, bond should escalate but doesn't
        if (posDepth == SPLIT_DEPTH) {
            // Should have special bond requirement at split boundary
            // BUG: Returns base calculation without escalation
        }

        // BOND-13: Minimum bond too low
        if (bond < MIN_BOND) {
            bond = MIN_BOND;
        }

        return bond;
    }

    // ========== RESOLUTION ==========

    /**
     * @dev Resolve the game
     *
     * DISPUTE-07: Resolution vulnerable to race condition
     * TIME-13:    Resolution/finalization race condition (no mutex)
     * TIME-14:    Game status change not atomic
     */
    function resolve() external returns (GameStatus) {
        // DISPUTE-07 / TIME-13: No mutex — race condition possible
        // BUG: No `require(status == GameStatus.IN_PROGRESS)` check
        // BUG: No `locked` guard — can be called concurrently

        // TIME-14: Status change not atomic
        // BUG: status set below but other state may be in flight

        // Check root claim
        ClaimData storage rootClaimData = claimData[0];

        if (rootClaimData.counteredBy == address(0)) {
            // DISPUTE-08: Root uncountered = defender wins
            // BUG: But what if counter's counter is uncountered?
            // counteredBy only tracks direct counter, not recursive resolution
            status = GameStatus.DEFENDER_WINS;
        } else {
            status = GameStatus.CHALLENGER_WINS;
        }

        emit Resolved(status);
        return status;
    }

    /**
     * @dev Resolve a specific subgame claim
     *
     * BOND-08: Subgame can be resolved multiple times
     * BOND-03: Bond distribution accounting error
     * BOND-04: Bond goes to wrong party
     */
    function resolveClaim(uint256 _claimIndex) external {
        // BOND-08: No check if already resolved
        // BUG: Missing `require(!resolvedSubgames[_claimIndex])` or `revert AlreadyResolved`

        ClaimData storage claim = claimData[_claimIndex];
        uint256 numToResolve = getNumToResolve(_claimIndex);

        // DISPUTE-06: Grandchild bond distribution can be skipped
        // BUG: Only looks at direct children, not recursive subgames
        // _resolveInternal doesn't recurse into grandchild subgames

        // BOND-04: Bond goes to wrong party
        // BUG: recipient = claimant instead of counteredBy
        address recipient = claim.claimant;
        if (claim.counteredBy != address(0)) {
            // BUG: subgameRootClaim checked but not used to determine correct winner
            recipient = claim.counteredBy;
        }

        // BOND-03: Bond distribution accounting error
        // BUG: credit[recipient] += bond without SafeTransfer/CEI pattern
        // BOND-10: Credit addition may overflow silently
        credit[recipient] += claim.bond;

        // BOND-08: Mark resolved (but check was missing above!)
        resolvedSubgames[_claimIndex] = true;
    }

    /**
     * @dev Get number of subgames to resolve for a claim
     */
    function getNumToResolve(uint256 _claimIndex) public view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < claimData.length; i++) {
            if (claimData[i].parentIndex == uint32(_claimIndex)) {
                count++;
            }
        }
        return count;
    }

    // ========== BOND CREDIT SYSTEM ==========

    /**
     * @dev Claim accumulated credit
     *
     * DISPUTE-13: Credit can be stolen by non-claimant — no onlyClaimant check
     * BOND-07:    Credit can be claimed multiple times — state update after transfer
     * BOND-16:    ETH transfer vulnerable to reentrancy — no ReentrancyGuard/CEI
     */
    function claimCredit(address _recipient) external {
        // DISPUTE-13: No access control — anyone can call with any _recipient
        // BUG: No `require(msg.sender == _recipient)` or onlyClaimant

        uint256 amount = credit[_recipient];
        require(amount > 0, "No credit");

        // BOND-16: ETH transfer before state update — reentrancy!
        // BUG: .call{value} BEFORE credit[_recipient] = 0

        // BOND-07: Vulnerable to double-claim via reentrancy
        (bool success,) = _recipient.call{value: amount}("");
        require(success, "Transfer failed");

        // BUG: State update AFTER external call (CEI violation)
        credit[_recipient] = 0;
    }

    // ========== DELAYED WETH ==========

    /**
     * @dev Unlock WETH from escrow
     *
     * BOND-11: DelayedWETH can be drained by unauthorized party
     * BOND-12: Unlock timing can be manipulated
     */
    function unlockBond(address guy, uint256 wad) external {
        // BOND-11: No onlyOwner / onlyGame check!
        // BUG: Anyone can call unlock for any address
        // Missing: require(msg.sender == game) or onlyGame modifier

        // BOND-12: Unlock timing — DELAY_SECONDS but no proper enforcement
        // BUG: unlockTime set but withdrawal doesn't verify it
        weth.unlock(guy, wad);
    }

    /**
     * @dev Withdraw WETH after delay
     *
     * BOND-12: Timing manipulation
     * BOND-15: Refund calculation error
     */
    function withdrawBond(address guy, uint256 wad) external {
        // BOND-12: No `require(block.timestamp >= unlockTime)` check here
        // BUG: Relies on weth contract to enforce, but we don't verify

        // BOND-15: Refund calculation — excess not returned
        // BUG: If msg.value - required = excess, the excess is lost
        uint256 excess = 0;
        if (wad > credit[guy]) {
            excess = wad - credit[guy];
            // BUG: excess not sent back with SafeTransfer
        }

        weth.withdraw(guy, wad);
    }

    // ========== BOND GRIEFING ==========

    /**
     * @dev BOND-13: Minimum bond enables griefing
     * BOND-14: Max depth allows excessive bond escalation
     *
     * Attacker can spam moves with MIN_BOND (0.001 ETH) to
     * grief the game tree. MAX_GAME_DEPTH of 73 means bond
     * can escalate to 2^73 * BASE_BOND = astronomical amounts.
     */
    function spamAttack(uint256 _parentIndex) external payable {
        // BOND-13: MIN_BOND too low — enables griefing attack
        // Cost: 0.001 ETH per move × many moves = cheap spam

        // BOND-14: MAX_GAME_DEPTH allows 73 levels of escalation
        // At depth 73: getRequiredBond = 0.08 ETH * 2^73 = overflow!

        require(msg.value >= MIN_BOND, "Insufficient bond");

        ClaimData storage parent = claimData[_parentIndex];
        uint128 nextPos = parent.position.attack();

        claimData.push(ClaimData({
            parentIndex: uint32(_parentIndex),
            counteredBy: address(0),
            claimant: msg.sender,
            bond: uint128(msg.value),
            claim: Claim.wrap(keccak256(abi.encodePacked(msg.sender, block.timestamp))),
            position: nextPos,
            clock: LibClock.wrap(0, uint64(block.timestamp))
        }));
    }

    // ========== DISPUTE-08: COUNTERED BY UNCOUNTERED ==========

    /**
     * @dev Check if a claim is effectively uncountered
     * DISPUTE-08: A claim countered by an uncountered counter can still win
     *
     * Scenario: claimA (defender) countered by claimB (challenger)
     * But claimB itself is uncountered → claimA should still win
     * BUG: This contract only checks direct counteredBy, not recursive
     */
    function isEffectivelyUncountered(uint256 _claimIndex) external view returns (bool) {
        ClaimData storage claim = claimData[_claimIndex];

        // BUG: Only checks direct counter, not whether counter is valid
        // counteredBy != address(0) doesn't mean the counter won
        return claim.counteredBy == address(0);
    }

    // ========== DISPUTE-09: SPLIT DEPTH EXPLOITATION ==========

    /**
     * @dev Attempt move at split depth boundary
     * DISPUTE-09: SPLIT_DEPTH boundary allows free moves
     *
     * At SPLIT_DEPTH, transition from output bisection to execution bisection
     * BUG: No _verifyExecBisection or revert ClaimAboveSplit
     */
    function moveAtSplitDepth(uint256 _parentIndex, Claim _claim) external payable {
        ClaimData storage parent = claimData[_parentIndex];
        uint128 nextPos = parent.position.attack();
        uint8 nextDepth = nextPos.depth();

        // DISPUTE-09: SPLIT_DEPTH + 1 or SPLIT_DEPTH - 1 exploitable
        // BUG: No check for `depth() <= SPLIT_DEPTH` or `revert ClaimAboveSplit`
        // BUG: No call to _verifyExecBisection at boundary

        claimData.push(ClaimData({
            parentIndex: uint32(_parentIndex),
            counteredBy: address(0),
            claimant: msg.sender,
            bond: uint128(msg.value),
            claim: _claim,
            position: nextPos,
            clock: LibClock.wrap(0, uint64(block.timestamp))
        }));
    }

    // ========== DISPUTE-11: PREIMAGE ORACLE ==========

    /**
     * @dev Load preimage data
     * DISPUTE-11: Preimage can be manipulated or front-run
     *
     * BUG: No check that keccak256(_stateData) matches expected pre-state
     * BUG: Anyone can front-run the loadPreimage call
     */
    function loadPreimage(bytes32 key, bytes calldata data) external {
        // BUG: keccak256(data) != key → should revert but doesn't
        // BUG: No access control — anyone can load any preimage
        oracle.loadPreimage(key, data);
    }

    /**
     * @dev Read preimage from oracle
     */
    function readPreimage(bytes32 key) external view returns (bytes32 val, uint256 len) {
        return oracle.readPreimage(key, 0);
    }

    // ========== DISPUTE-15: ROOT CLAIM MANIPULATION ==========

    /**
     * @dev DISPUTE-15: Root claim can be modified after initialization!
     * BUG: rootClaim is NOT immutable — it's a regular state variable
     * BUG: No access control on this function
     */
    function updateRootClaim(Claim _newRootClaim) external {
        // Should be: `Claim immutable rootClaim` set only in constructor
        // Or: created via DisputeGameFactory.create() with immutable
        rootClaim = _newRootClaim;
    }

    // ========== DISPUTE-16: ANCHOR STATE VALIDATION ==========

    /**
     * @dev DISPUTE-16: Extra data and anchor state not validated
     * BUG: No check that extraData matches anchorStateRegistry
     * BUG: startingBlockNumber can be arbitrary
     */
    function getAnchorState() external view returns (bytes32 root, uint256 l2BlockNumber) {
        // DISPUTE-16: anchorStateRegistry queried but result not validated
        (root, l2BlockNumber) = anchorStateRegistry.anchors(0);

        // BUG: No require(extraData matches anchor state)
        // BUG: No _validateAnchor call
    }

    // ========== BOND-09: CREDIT OVERFLOW ==========

    /**
     * @dev Add credit for a recipient
     * BOND-09: Credit accounting vulnerable to overflow
     * BOND-10: Credit addition may overflow silently
     */
    function addCredit(address _recipient, uint256 _amount) external {
        // BOND-09 / BOND-10: No SafeMath or checked arithmetic guard
        // BUG: credit[_recipient] + _amount can overflow
        // BUG: No require(credit[_recipient] + _amount >= credit[_recipient])
        credit[_recipient] += _amount;
    }

    // ========== DISPUTE-02: GRANDPARENT CLOCK ==========

    /**
     * @dev Get challenger duration using grandparent clock
     * DISPUTE-02: Grandparent clock inheritance exploitable
     */
    function getChallengerDuration(uint256 _claimIndex) external view returns (uint64) {
        ClaimData storage claim = claimData[_claimIndex];

        // DISPUTE-02: Uses parent.clock() without Duration.unwrap > MIN check
        // BUG: Uses grandparentClock directly, no LibClock.wrap validation
        if (claim.parentIndex != type(uint32).max) {
            ClaimData storage parentClaim = claimData[claim.parentIndex];
            uint128 grandparentClock = parentClaim.clock;
            return grandparentClock.duration();
        }
        return 0;
    }

    // ========== TIME-12: CLOCK INHERITANCE ==========

    /**
     * @dev Validate clock for a move
     * TIME-12: Clock inheritance can be exploited
     * BUG: No check that clock > parent.clock
     */
    function validateClock(uint256 _claimIndex) external view returns (bool) {
        ClaimData storage claim = claimData[_claimIndex];
        if (claim.parentIndex == type(uint32).max) return true;

        ClaimData storage parentClaim = claimData[claim.parentIndex];

        // TIME-12: BUG: No validation that child clock > parent clock
        // An attacker can set clock to any value
        return claim.clock.duration() > 0;
    }

    // ========== HELPERS ==========

    function claimDataLen() external view returns (uint256) {
        return claimData.length;
    }

    function gameType() external pure returns (uint32) {
        return 0; // CANNON
    }

    /// @dev Accept ETH for bond deposits
    receive() external payable {}
}
