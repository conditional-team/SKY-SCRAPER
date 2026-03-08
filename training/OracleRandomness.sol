// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title OracleRandomness
 * @dev Training Contract #30 - Oracle Advanced + Randomness / Games
 *
 * VULNERABILITY CATEGORIES:
 * 1. Oracle Feed Spoofing Cross-Chain (ORACLE-ADV-01)
 * 2. Collateral Misvaluation via Oracle (ORACLE-ADV-02)
 * 3. Lottery Manipulation (RAND-01)
 * 4. VRF Seed Reuse (RAND-02)
 * 5. Miner-Controllable Randomness (RAND-03)
 * 6. VRF Callback Manipulation (RAND-ADV-01)
 * 7. Lottery Result Pre-Computation (RAND-ADV-02)
 * 8. Gambling Outcome Timing (RAND-ADV-03)
 * 9. Commit-Reveal Timeout Exploit (RAND-ADV-04)
 * 10. Prediction Market Oracle Gaming (RAND-ADV-05)
 * 11. Provably Unfair Game (RAND-ADV-06)
 * 12. On-Chain Poker Exploit (RAND-ADV-07)
 * 13. Dice Roll Manipulation (RAND-ADV-08)
 * 14. Slot Machine Seed Leak (RAND-ADV-09)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): ORACLE-ADV-*, RAND-*, RAND-ADV-*
 * - Engine 10 (ghost-state-detector): stale oracle reads
 * - Engine 4 (temporal-analyzer): timestamp dependence
 */

// ========== VULN 1: Oracle Feed Spoofing Cross-Chain (ORACLE-ADV-01) ==========

contract CrossChainOracle {
    mapping(address => uint256) public prices;
    mapping(address => bool) public trustedRelayers;
    address public owner;

    constructor() { owner = msg.sender; }

    // BUG #1: L2 oracle accepts prices from "relayer" without verifying L1 proof
    // Attacker compromises or impersonates relayer to feed fake prices
    function updatePriceFromL1(
        address token, uint256 price, bytes calldata proof
    ) external {
        // VULN: relayer check but no L1 state proof verification
        require(trustedRelayers[msg.sender], "not relayer");
        // Should verify Merkle proof against L1 state root
        prices[token] = price;
    }

    function getPrice(address token) external view returns (uint256) {
        return prices[token];
    }
}

// ========== VULN 2: Collateral Misvaluation (ORACLE-ADV-02) ==========

contract LendingWithOracle {
    CrossChainOracle public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant LTV = 80; // 80%

    constructor(address _oracle) {
        oracle = CrossChainOracle(_oracle);
    }

    function deposit(address token, uint256 amount) external {
        collateral[msg.sender] += amount;
    }

    // BUG #2: flashloan → pump oracle → borrow max → dump oracle
    // Oracle price manipulable within single tx
    function borrow(address collateralToken, uint256 borrowAmount) external {
        uint256 price = oracle.getPrice(collateralToken);
        uint256 collateralValue = collateral[msg.sender] * price / 1e18;
        uint256 maxBorrow = collateralValue * LTV / 100;
        require(debt[msg.sender] + borrowAmount <= maxBorrow, "undercollateralized");
        debt[msg.sender] += borrowAmount;
        // ... transfer borrowed tokens
    }
}

// ========== VULNS 3-5: Basic Randomness (RAND-01, RAND-02, RAND-03) ==========

contract VulnerableLottery {
    uint256 public ticketPrice = 0.01 ether;
    uint256 public jackpot;
    mapping(uint256 => address) public tickets;
    uint256 public ticketCount;
    uint256 public drawBlock;
    uint256 public lastRequestId;

    mapping(uint256 => bytes32) public vrfSeeds;
    mapping(bytes32 => bool) public commitments;
    mapping(bytes32 => uint256) public commitBlock;

    event LotteryResult(address winner, uint256 amount, uint256 randomNumber);

    function buyTicket() external payable {
        require(msg.value >= ticketPrice, "underpaid");
        tickets[ticketCount++] = msg.sender;
        jackpot += msg.value;
    }

    // BUG #3: RAND-01 — on-chain randomness from block data
    function drawWinner() external {
        require(ticketCount > 0, "no tickets");
        // VULN: block.timestamp and blockhash are public, miner-influenceable
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp, blockhash(block.number - 1), ticketCount
        )));
        uint256 winnerIndex = random % ticketCount;
        address winner = tickets[winnerIndex];
        emit LotteryResult(winner, jackpot, random);
        payable(winner).transfer(jackpot);
        jackpot = 0;
    }

    // BUG #4: RAND-02 — VRF seed reuse
    function requestRandom(bytes32 seed) external returns (uint256 requestId) {
        requestId = ++lastRequestId;
        // VULN: same seed produces same requestId hash, enabling pre-computation
        vrfSeeds[requestId] = seed;
    }

    // BUG #5: RAND-03 — block.prevrandao (ex-difficulty) controllable by validator
    function minerLottery() external view returns (uint256) {
        // VULN: validator/miner can choose to withhold block if result unfavorable
        return uint256(keccak256(abi.encodePacked(block.prevrandao, msg.sender))) % 100;
    }
}

// ========== VULNS 6-14: Randomness Advanced (RAND-ADV-01→09) ==========

contract RandomnessExploits {
    address public vrfCoordinator;
    uint256 public lastResult;
    mapping(uint256 => address) public requestToUser;
    mapping(uint256 => uint256) public requestToAmount;
    mapping(address => uint256) public playerBalances;

    // Game state
    mapping(address => bytes32) public playerCommits;
    mapping(address => uint256) public commitTimestamp;
    uint256 public constant REVEAL_TIMEOUT = 1 hours;

    // Prediction market
    mapping(bytes32 => uint256) public marketBets;
    mapping(bytes32 => address) public marketOracle;
    uint256 public houseEdge = 500; // 5%

    // Poker
    mapping(address => uint8[5]) public playerHands;
    uint8[52] public deck;
    uint8 public deckIndex;

    // Slots
    uint256 public slotSeed;

    event GameResult(address player, uint256 result, bool won);
    event SlotResult(address player, uint256 seed, uint8[3] reels);

    constructor() {
        vrfCoordinator = msg.sender;
        slotSeed = uint256(keccak256(abi.encodePacked(block.timestamp)));
    }

    // BUG #6: RAND-ADV-01 — VRF callback doesn't verify requestId/sender
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external {
        // VULN: no check that msg.sender == vrfCoordinator
        // VULN: no check that requestId was actually requested
        address user = requestToUser[requestId];
        uint256 betAmount = requestToAmount[requestId];
        lastResult = randomWords[0];

        if (randomWords[0] % 2 == 0) {
            playerBalances[user] += betAmount * 2;
        }
    }

    // BUG #7: RAND-ADV-02 — lottery result computable from public data
    function weeklyLottery() external view returns (uint256 winnerIndex) {
        // VULN: all inputs are public on-chain, result can be pre-computed
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.number, block.timestamp, block.prevrandao, address(this).balance
        )));
        return random % 1000;
    }

    // BUG #8: RAND-ADV-03 — bet and resolve in same tx
    function instantGame() external payable returns (bool won) {
        require(msg.value > 0, "no bet");
        // VULN: result determined and settled in same tx
        // Attacker wraps in try/catch: revert if lost
        uint256 result = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
        won = result % 2 == 0;
        if (won) {
            payable(msg.sender).transfer(msg.value * 2);
        }
        emit GameResult(msg.sender, result, won);
    }

    // BUG #9: RAND-ADV-04 — no reveal timeout
    function commit(bytes32 hash) external payable {
        playerCommits[msg.sender] = hash;
        commitTimestamp[msg.sender] = block.timestamp;
        playerBalances[msg.sender] += msg.value;
    }

    function reveal(uint256 choice, bytes32 salt) external {
        require(keccak256(abi.encodePacked(choice, salt)) == playerCommits[msg.sender], "bad reveal");
        // VULN: no timeout — player can simply NOT reveal if outcome is bad
        // Funds remain locked with commit, no expiry mechanism
        playerCommits[msg.sender] = bytes32(0);
        // ... game logic
    }

    // BUG #10: RAND-ADV-05 — prediction market oracle gaming
    function createPredictionMarket(bytes32 marketId, address oracleAddr) external {
        marketOracle[marketId] = oracleAddr;
    }

    function betOnMarket(bytes32 marketId, bool outcome) external payable {
        // VULN: oracle manipulation cost < bet profit potential
        // Attacker manipulates oracle, then resolves market for guaranteed win
        marketBets[marketId] += msg.value;
    }

    // BUG #11: RAND-ADV-06 — provably unfair game
    function setHouseEdge(uint256 newEdge) external {
        // VULN: house edge changeable AFTER bets placed
        // Owner sees losing bet for house, increases edge before resolution
        houseEdge = newEdge; // no cap, no timelock
    }

    // BUG #12: RAND-ADV-07 — cards visible in state/calldata
    function dealCards(address player) external {
        for (uint i = 0; i < 5; i++) {
            // VULN: cards stored in public mapping — anyone can read them
            playerHands[player][i] = deck[deckIndex++];
        }
    }

    // BUG #13: RAND-ADV-08 — dice from prevrandao
    function rollDice() external view returns (uint8) {
        // VULN: block.prevrandao known to validator, can be influenced
        return uint8(uint256(keccak256(abi.encodePacked(block.prevrandao))) % 6) + 1;
    }

    // BUG #14: RAND-ADV-09 — seed leaked in events/storage
    function spinSlots() external {
        // VULN: seed is in public storage and emitted in event
        slotSeed = uint256(keccak256(abi.encodePacked(slotSeed, block.timestamp)));
        uint8 reel1 = uint8(slotSeed % 10);
        uint8 reel2 = uint8((slotSeed >> 8) % 10);
        uint8 reel3 = uint8((slotSeed >> 16) % 10);
        emit SlotResult(msg.sender, slotSeed, [reel1, reel2, reel3]);
    }
}
