// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IntentMEV
 * @dev Training Contract #23 - Intent Architecture & MEV Vulnerabilities (2026)
 * 
 * VULNERABILITY CATEGORIES:
 * 1. Intent replay across chains (missing chain ID)
 * 2. Intent replay across time (no expiry / stale intent)
 * 3. Solver collusion (solvers cooperate to extract user value)
 * 4. Partial fill manipulation (fill minimum, pocket remainder)
 * 5. Cross-domain MEV (extract value across L1+L2 simultaneously)
 * 6. Shared sequencing front-running (sequencer sees intents)
 * 7. Phantom function call (low-level call to missing function returns success)
 * 8. Returndata bomb (huge returndata consumes all gas)
 * 9. Unbounded loop DoS (gas griefing via array size)
 * 10. Order-dependent state (tx ordering changes outcome)
 * 11. Solver censorship (solver refuses to fill for specific users)
 * 12. Intent front-running (solver copies user's intent strategy)
 * 13. Back-running profit extraction
 * 14. JIT liquidity attack (provide liquidity → user trades → remove)
 * 15. Time-bandit attack (reorg for MEV profit)
 *
 * REAL-WORLD CONTEXT:
 * - Intent-based protocols: UniswapX, CoWSwap, 1inch Fusion
 * - Cross-domain MEV: SUAVE, Flashbots MEV-Share
 * - Shared sequencing: Espresso, Astria
 * - These represent the NEXT FRONTIER of smart contract security
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 4: Temporal (intent timing, expiry)
 * - Engine 6: Token Flow (partial fills, MEV extraction)
 * - Engine 9: Access Control (solver permissions)
 * - Engine 17: Cross-Contract (cross-domain MEV)
 * - Engine 25: Finality (reorg attacks)
 * - Engine 21: Bleeding Edge (intent architecture, shared sequencing)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 15_SandwichableView (price oracle manipulation for solver)
 * - Links to 07_FlashLoanVictim (flash loan within intent settlement)
 * - Links to 14_SequencerDownOracle (sequencer-controlled ordering)
 */

// ========== INTERFACES ==========

interface ISandwichableView {
    function getRate() external view returns (uint256);
    function swap(uint256 amountIn, bool direction) external returns (uint256);
}

interface IFlashLoanVictim {
    function getPrice() external view returns (uint256);
    function flashLoan(uint256 amount) external;
}

interface ISequencerDownOracle {
    function isSequencerUp() external view returns (bool);
    function getPriceUnsafe() external view returns (uint256);
}

// ========== MAIN CONTRACT ==========

contract IntentMEV {
    // === INTENT STATE ===
    
    struct Intent {
        address user;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;  // Slippage tolerance
        uint256 deadline;
        uint256 nonce;
        bytes32 intentHash;
        bool filled;
        bool cancelled;
        address solver;        // Who filled this intent
        uint256 filledAmount;  // How much was filled
        uint256 tip;           // MEV tip for solver priority
    }
    
    mapping(bytes32 => Intent) public intents;
    mapping(address => uint256) public userNonces;
    mapping(address => uint256) public userBalances;
    
    // Solver registry
    mapping(address => bool) public registeredSolvers;
    mapping(address => uint256) public solverStake;
    mapping(address => uint256) public solverReputation;
    uint256 public constant MIN_SOLVER_STAKE = 1 ether;
    
    // Order book (simplified)
    bytes32[] public pendingIntents;
    mapping(bytes32 => uint256) public intentIndex;
    
    // MEV auction
    struct MEVBid {
        address solver;
        uint256 bidAmount;
        bytes32 intentHash;
        bytes solution; // Encoded swap path
    }
    
    mapping(bytes32 => MEVBid[]) public bids;
    
    // Cross-domain state
    mapping(uint256 => mapping(bytes32 => bool)) public crossChainFilled;
    
    // 🔗 CHAIN
    ISandwichableView public oracle;
    IFlashLoanVictim public flashLoan;
    ISequencerDownOracle public sequencerOracle;
    
    address public owner;
    address public sequencer;
    
    event IntentSubmitted(bytes32 indexed hash, address indexed user, uint256 amountIn);
    event IntentFilled(bytes32 indexed hash, address indexed solver, uint256 amountOut);
    event IntentCancelled(bytes32 indexed hash);
    event SolverRegistered(address indexed solver, uint256 stake);
    
    constructor(address _sequencer) {
        owner = msg.sender;
        sequencer = _sequencer;
    }
    
    function setExternalContracts(
        address _oracle,
        address _flashLoan,
        address _sequencerOracle
    ) external {
        // BUG: No access control
        oracle = ISandwichableView(_oracle);
        flashLoan = IFlashLoanVictim(_flashLoan);
        sequencerOracle = ISequencerDownOracle(_sequencerOracle);
    }

    // ========== VULNERABILITY #1: INTENT CROSS-CHAIN REPLAY ==========
    
    /**
     * @dev Submit a swap intent
     * BUG #1: Intent hash doesn't include chain ID or contract address
     * Same intent valid on Ethereum, Arbitrum, Optimism, Base...
     * 
     * Attack: User submits intent on mainnet → solver replays on L2
     * where price is different → solver profits from price discrepancy
     */
    function submitIntent(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 deadline,
        uint256 tip
    ) external payable returns (bytes32) {
        require(msg.value >= amountIn + tip, "Insufficient value");
        
        uint256 nonce = userNonces[msg.sender]++;
        
        // BUG #1: Missing block.chainid and address(this) in hash!
        bytes32 intentHash = keccak256(abi.encodePacked(
            msg.sender,
            tokenIn,
            tokenOut,
            amountIn,
            minAmountOut,
            deadline,
            nonce
            // Missing: block.chainid, address(this)
        ));
        
        intents[intentHash] = Intent({
            user: msg.sender,
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            deadline: deadline,
            nonce: nonce,
            intentHash: intentHash,
            filled: false,
            cancelled: false,
            solver: address(0),
            filledAmount: 0,
            tip: tip
        });
        
        pendingIntents.push(intentHash);
        intentIndex[intentHash] = pendingIntents.length - 1;
        
        userBalances[msg.sender] += amountIn;
        
        emit IntentSubmitted(intentHash, msg.sender, amountIn);
        return intentHash;
    }

    // ========== VULNERABILITY #2: STALE INTENT EXPLOITATION ==========
    
    /**
     * @dev Fill an intent
     * BUG #2: Deadline only checks block.timestamp, not price staleness
     * Intent with 24h deadline can be filled when market moved 50%
     * Solver fills at user's old price expectation → extracts MEV
     */
    function fillIntent(bytes32 intentHash, uint256 amountOut) external {
        Intent storage intent = intents[intentHash];
        
        require(!intent.filled, "Already filled");
        require(!intent.cancelled, "Cancelled");
        
        // BUG #2: Only checks deadline, not price freshness
        require(block.timestamp <= intent.deadline, "Expired");
        
        // BUG #2: minAmountOut was set when intent was created
        // Market may have moved significantly since then
        // Solver fills at minimum (user gets worst price within tolerance)
        require(amountOut >= intent.minAmountOut, "Below minimum");
        
        // BUG #11: No solver registration check!
        // Anyone can fill, including malicious actors
        // require(registeredSolvers[msg.sender], "Not registered");
        
        intent.filled = true;
        intent.solver = msg.sender;
        intent.filledAmount = amountOut;
        
        // Transfer user's input to solver
        userBalances[intent.user] -= intent.amountIn;
        
        // Transfer output to user
        (bool success, ) = intent.user.call{value: amountOut}("");
        require(success, "Transfer to user failed");
        
        // Pay solver tip
        if (intent.tip > 0) {
            (success, ) = msg.sender.call{value: intent.tip}("");
            require(success, "Tip transfer failed");
        }
        
        emit IntentFilled(intentHash, msg.sender, amountOut);
    }

    // ========== VULNERABILITY #3: SOLVER COLLUSION ==========
    
    /**
     * @dev MEV auction for intent filling rights
     * BUG #3: Solvers can collude to submit low bids together
     * No competitive pressure if all solvers agree on extractable value
     * 
     * BUG #3b: Bid amounts visible on-chain → last-mover advantage
     * Solver waits to see others' bids, then bids just above highest
     */
    function submitBid(bytes32 intentHash, uint256 bidAmount, bytes calldata solution) external {
        require(registeredSolvers[msg.sender], "Not registered");
        
        Intent storage intent = intents[intentHash];
        require(!intent.filled, "Already filled");
        
        // BUG #3: No mechanism to prevent collusion
        // If only 2 solvers exist, they can agree to alternate winning
        // extracting maximum value from users
        
        // BUG #3b: Bids stored publicly — last bidder sees all previous bids
        bids[intentHash].push(MEVBid({
            solver: msg.sender,
            bidAmount: bidAmount,
            intentHash: intentHash,
            solution: solution
        }));
    }
    
    /**
     * @dev Settle auction — highest bid wins
     * BUG #3c: Winning solver keeps ALL surplus between bid and actual execution
     */
    function settleAuction(bytes32 intentHash) external {
        MEVBid[] storage intentBids = bids[intentHash];
        require(intentBids.length > 0, "No bids");
        
        // Find highest bid
        uint256 highestBid;
        uint256 winnerIdx;
        for (uint i = 0; i < intentBids.length; i++) {
            if (intentBids[i].bidAmount > highestBid) {
                highestBid = intentBids[i].bidAmount;
                winnerIdx = i;
            }
        }
        
        // BUG #9: Unbounded loop — if many bids, gas can exceed block limit
        // DoS vector: submit thousands of dust bids
        
        // BUG #3c: Solver bid X but might execute for X+surplus
        // Surplus goes to solver, not user
        MEVBid storage winner = intentBids[winnerIdx];
        
        // Execute winning solution (simplified)
        Intent storage intent = intents[intentHash];
        intent.filled = true;
        intent.solver = winner.solver;
        intent.filledAmount = winner.bidAmount;
    }

    // ========== VULNERABILITY #4: PARTIAL FILL MANIPULATION ==========
    
    /**
     * @dev Allow partial intent fills
     * BUG #4: Solver fills minimum amount, keeps remainder as MEV
     * User's intent for 100 tokens filled with 50 at minimum price
     * 
     * BUG #4b: No check that total partial fills don't exceed intent
     */
    uint256 public constant MIN_FILL_PERCENT = 10; // 10% minimum
    
    mapping(bytes32 => uint256) public totalFilled;
    
    function partialFill(bytes32 intentHash, uint256 fillAmount) external {
        Intent storage intent = intents[intentHash];
        require(!intent.filled, "Fully filled");
        require(!intent.cancelled, "Cancelled");
        
        // BUG #4: Minimum fill is only 10% — solver can drip-fill at worst price
        // Each 10% fill uses the minimum price, extracting value each time
        uint256 minFill = (intent.amountIn * MIN_FILL_PERCENT) / 100;
        require(fillAmount >= minFill, "Below minimum fill");
        
        // BUG #4b: No proper tracking of cumulative fills
        totalFilled[intentHash] += fillAmount;
        
        // BUG #4b: Can exceed 100% if multiple solvers race
        // No check: require(totalFilled[intentHash] <= intent.amountIn)
        
        if (totalFilled[intentHash] >= intent.amountIn) {
            intent.filled = true;
        }
        
        // Calculate proportional output
        uint256 outputAmount = (fillAmount * intent.minAmountOut) / intent.amountIn;
        
        // BUG #4: Always fills at exact minimum — no price improvement
        (bool success, ) = intent.user.call{value: outputAmount}("");
        require(success, "Transfer failed");
    }

    // ========== VULNERABILITY #5: CROSS-DOMAIN MEV ==========
    
    /**
     * @dev Cross-domain intent settlement
     * 🔗 CHAIN: SandwichableView + FlashLoanVictim → IntentMEV
     * 
     * BUG #5: Solver executes across L1+L2 atomically
     * Flash loan on L1 → manipulate price → fill intent on L2 at manipulated price
     * User gets worse rate, solver profits from cross-domain arbitrage
     */
    function fillCrossDomain(
        bytes32 intentHash,
        uint256 sourceChainId,
        uint256 amountOut
    ) external {
        Intent storage intent = intents[intentHash];
        require(!intent.filled, "Already filled");
        
        // BUG #5: No verification that fill on source chain actually happened
        // Solver claims "I filled on L2" without proof
        require(!crossChainFilled[sourceChainId][intentHash], "Already filled cross-chain");
        
        // BUG #5: Uses local oracle which can be flash-manipulated
        uint256 currentPrice;
        if (address(oracle) != address(0)) {
            currentPrice = oracle.getRate(); // BUG: Spot price, manipulable!
        } else {
            currentPrice = 1e18;
        }
        
        // BUG #5: Cross-domain price discrepancy = free money for solver
        // Price on chain A != price on chain B → arbitrage
        
        crossChainFilled[sourceChainId][intentHash] = true;
        intent.filled = true;
        intent.solver = msg.sender;
        intent.filledAmount = amountOut;
        
        (bool success, ) = intent.user.call{value: amountOut}("");
        require(success, "Transfer failed");
    }

    // ========== VULNERABILITY #6: SHARED SEQUENCING FRONT-RUN ==========
    
    /**
     * @dev Submit intent via shared sequencer
     * BUG #6: Sequencer sees intent before inclusion → front-runs
     * 
     * Shared sequencing (Espresso/Astria): single sequencer for multiple L2s
     * Sequencer observes all L2 intents → extracts cross-L2 MEV
     * Users have ZERO protection from sequencer MEV
     */
    function submitViaSequencer(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external payable returns (bytes32) {
        require(msg.value >= amountIn, "Insufficient");
        
        // BUG #6: Intent data is public — sequencer sees everything
        // In shared sequencing model:
        // 1. Sequencer receives intent
        // 2. Sequencer inserts front-running tx before user's
        // 3. User's intent executes at worse price
        // 4. Sequencer back-runs to close position
        // = sandwich without mempool, impossible to detect
        
        // BUG #6b: No commit-reveal scheme
        // Should: Step 1: commit(hash) → Step 2: reveal(intent) after inclusion
        // Without this, sequencer has perfect information advantage
        
        uint256 nonce = userNonces[msg.sender]++;
        bytes32 intentHash = keccak256(abi.encodePacked(
            msg.sender, tokenIn, tokenOut, amountIn, minAmountOut, nonce
        ));
        
        intents[intentHash] = Intent({
            user: msg.sender,
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            deadline: block.timestamp + 1 hours,
            nonce: nonce,
            intentHash: intentHash,
            filled: false,
            cancelled: false,
            solver: address(0),
            filledAmount: 0,
            tip: 0
        });
        
        pendingIntents.push(intentHash);
        userBalances[msg.sender] += amountIn;
        
        return intentHash;
    }

    // ========== VULNERABILITY #7: PHANTOM FUNCTION CALL ==========
    
    /**
     * @dev Call solver's settlement contract
     * BUG #7: Low-level call to address with no code returns success
     * If solver_contract has no matching function, call succeeds with empty returndata
     * Contract assumes settlement happened, but nothing executed
     */
    function executeSolverSettlement(
        address solverContract,
        bytes calldata settlementData
    ) external {
        // BUG #7: No check that solverContract has code
        // call to EOA or empty address returns (true, "")
        // Contract thinks settlement succeeded when nothing happened
        
        (bool success, bytes memory returnData) = solverContract.call(settlementData);
        
        // BUG #7: success=true even if contract doesn't exist!
        // Should check: require(solverContract.code.length > 0)
        require(success, "Settlement failed");
        
        // BUG #7b: No validation of returnData
        // Empty returndata = function doesn't exist = phantom success
    }

    // ========== VULNERABILITY #8: RETURNDATA BOMB ==========
    
    /**
     * @dev Get quote from solver
     * BUG #8: Solver can return massive data → consumes all gas
     * Caller has to pay for copying returndata even if it's garbage
     * 
     * Attack: Malicious solver returns 10MB of data → OOG for caller
     */
    function getQuoteFromSolver(
        address solver,
        bytes32 intentHash
    ) external returns (uint256 quote) {
        // BUG #8: returndata bomb — no size limit on returned data
        // Malicious solver's getQuote() returns bytes(10_000_000)
        // The returndatacopy in this call context copies ALL of it → OOG
        
        (bool success, bytes memory data) = solver.call(
            abi.encodeWithSignature("getQuote(bytes32)", intentHash)
        );
        
        // BUG #8: Even if we only need 32 bytes (uint256),
        // Solidity copies ALL returndata into memory first
        // Should use assembly to limit returndatacopy size
        
        if (success && data.length >= 32) {
            quote = abi.decode(data, (uint256));
        }
    }

    // ========== VULNERABILITY #9: UNBOUNDED LOOP DOS ==========
    
    /**
     * @dev Get all pending intents
     * BUG #9: Unbounded array iteration → gas limit DoS
     * If pendingIntents has 10K entries, iterating costs >30M gas
     * Contract becomes unusable once array grows large enough
     */
    function getAllPendingIntents() external view returns (bytes32[] memory) {
        // BUG #9: Returns entire array — no pagination
        // At some point, this exceeds block gas limit
        return pendingIntents;
    }
    
    /**
     * @dev Cancel all expired intents
     * BUG #9b: Unbounded loop over all intents
     */
    function cleanupExpiredIntents() external {
        // BUG #9b: O(n) loop, n grows without bound
        for (uint i = 0; i < pendingIntents.length; i++) {
            Intent storage intent = intents[pendingIntents[i]];
            if (block.timestamp > intent.deadline && !intent.filled) {
                intent.cancelled = true;
                // BUG: Doesn't remove from pendingIntents array → grows forever
            }
        }
    }

    // ========== VULNERABILITY #10: ORDER-DEPENDENT STATE ==========
    
    /**
     * @dev Batch fill multiple intents
     * BUG #10: Order of fills changes final state
     * Tx A fills intent at price X, changes pool state
     * Tx B now fills at different price due to A's state change
     * Solver controls ordering → controls which user gets which price
     */
    function batchFill(
        bytes32[] calldata intentHashes,
        uint256[] calldata amounts
    ) external {
        require(intentHashes.length == amounts.length, "Length mismatch");
        
        for (uint i = 0; i < intentHashes.length; i++) {
            Intent storage intent = intents[intentHashes[i]];
            
            if (intent.filled || intent.cancelled) continue;
            
            // BUG #10: Each fill may change oracle price
            // Order matters: intent[0] fills at price X, intent[1] at price Y
            // Solver reorders to maximize own profit
            
            // BUG #10: Uses live oracle price which changes during batch
            uint256 currentPrice = 1e18;
            if (address(oracle) != address(0)) {
                currentPrice = oracle.getRate(); // Changes between iterations!
            }
            
            uint256 outputAmount = (intent.amountIn * currentPrice) / 1e18;
            require(outputAmount >= intent.minAmountOut, "Slippage");
            
            intent.filled = true;
            intent.solver = msg.sender;
            intent.filledAmount = outputAmount;
            
            // BUG #10: State changes affect subsequent iterations
            (bool success, ) = intent.user.call{value: outputAmount}("");
            require(success, "Transfer failed");
        }
    }

    // ========== VULNERABILITY #13-14: BACK-RUNNING & JIT LIQUIDITY ==========
    
    /**
     * @dev On-chain intent reveals swap details → back-running
     * BUG #13: After user's intent fills, back-runner captures remaining value
     * 
     * BUG #14: JIT liquidity attack
     * 1. Solver sees large intent pending
     * 2. Adds concentrated liquidity at user's price
     * 3. User fills against this liquidity (solver earns fees)
     * 4. Solver removes liquidity immediately after
     * = solver earns risk-free fees at user's expense
     */
    function fillWithJITLiquidity(
        bytes32 intentHash,
        uint256 liquidityAmount
    ) external payable {
        Intent storage intent = intents[intentHash];
        require(!intent.filled, "Already filled");
        
        // BUG #14: Solver provides EXACT liquidity for this intent
        // Then removes it immediately after fill
        // Risk-free fee extraction from the user's trade
        
        // Step 1: Solver adds liquidity (in same tx as fill)
        // Step 2: User's intent executes against this liquidity
        // Step 3: Solver removes liquidity (also same tx)
        
        uint256 price = 1e18;
        if (address(oracle) != address(0)) {
            price = oracle.getRate();
        }
        
        uint256 outputAmount = (intent.amountIn * price) / 1e18;
        require(outputAmount >= intent.minAmountOut, "Below minimum");
        
        intent.filled = true;
        intent.solver = msg.sender;
        intent.filledAmount = outputAmount;
        
        // Pay user (minus JIT fee, disguised as "market impact")
        uint256 jitFee = outputAmount / 100; // 1% hidden fee
        // BUG #14: User gets less than market price, solver keeps the fee
        (bool success, ) = intent.user.call{value: outputAmount - jitFee}("");
        require(success, "Transfer failed");
        
        emit IntentFilled(intentHash, msg.sender, outputAmount - jitFee);
    }

    // ========== VULNERABILITY #15: TIME-BANDIT REORG ATTACK ==========
    
    /**
     * @dev Intent with reorg vulnerablility
     * BUG #15: Profitable intent fills can be reorged
     * Attacker with enough hashpower/stake reorgs the chain
     * to replace the original solver with themselves
     * 
     * Especially dangerous on PoS chains with low stake requirements
     */
    function fillWithReorgProtection(
        bytes32 intentHash,
        uint256 amountOut,
        bytes32 parentBlockHash
    ) external {
        // Attempt at reorg protection
        // BUG #15: parentBlockHash check is insufficient
        // Attacker can reorg AFTER this block, including a new fill
        require(
            blockhash(block.number - 1) == parentBlockHash,
            "Reorg detected"
        );
        // BUG #15: blockhash only works for last 256 blocks
        // And the check only validates the parent, not deeper ancestors
        
        Intent storage intent = intents[intentHash];
        require(!intent.filled, "Already filled");
        require(amountOut >= intent.minAmountOut, "Below minimum");
        
        intent.filled = true;
        intent.solver = msg.sender;
        intent.filledAmount = amountOut;
        
        // BUG #15: If block gets reorged, this fill is replaced
        // Attacker's fill executes instead with worse terms for user
        (bool success, ) = intent.user.call{value: amountOut}("");
        require(success, "Transfer failed");
    }

    // ========== SOLVER MANAGEMENT ==========
    
    /**
     * @dev Register as solver
     * BUG #11b: Minimum stake too low for the value being secured
     */
    function registerSolver() external payable {
        require(msg.value >= MIN_SOLVER_STAKE, "Insufficient stake");
        
        // BUG #11b: 1 ETH stake can fill intents worth millions
        // Stake should be proportional to intent value
        registeredSolvers[msg.sender] = true;
        solverStake[msg.sender] += msg.value;
        solverReputation[msg.sender] = 100; // Starting reputation
        
        emit SolverRegistered(msg.sender, msg.value);
    }
    
    /**
     * @dev Cancel intent
     * BUG #12: Cancellation can be front-run by solver
     * User submits cancel → solver sees it → fills before cancel executes
     */
    function cancelIntent(bytes32 intentHash) external {
        Intent storage intent = intents[intentHash];
        require(intent.user == msg.sender, "Not your intent");
        require(!intent.filled, "Already filled");
        
        // BUG #12: Between this tx entering mempool and being included,
        // solver can front-run with a fill at minimum price
        // User gets minimum instead of cancellation
        
        intent.cancelled = true;
        
        // Return funds
        if (userBalances[msg.sender] >= intent.amountIn) {
            userBalances[msg.sender] -= intent.amountIn;
            (bool success, ) = msg.sender.call{value: intent.amountIn + intent.tip}("");
            require(success, "Refund failed");
        }
        
        emit IntentCancelled(intentHash);
    }

    receive() external payable {}
}

/**
 * @title MaliciousSolver
 * @dev Demonstrates solver extraction attacks
 */
contract MaliciousSolver {
    IntentMEV public target;
    
    constructor(address payable _target) {
        target = IntentMEV(_target);
    }
    
    /**
     * @dev getQuote returns massive data → returndata bomb (BUG #8)
     */
    function getQuote(bytes32 /* intentHash */) external pure returns (bytes memory) {
        // Return 1MB of garbage data → caller pays for copying
        bytes memory bomb = new bytes(1_000_000);
        return bomb;
    }
    
    /**
     * @dev Sandwich: front-run intent fill with price manipulation
     */
    function sandwichFill(
        bytes32 intentHash,
        address oracleAddr,
        uint256 manipulateAmount
    ) external payable {
        // Step 1: Manipulate price
        ISandwichableView oracle = ISandwichableView(oracleAddr);
        oracle.swap(manipulateAmount, true); // Push price up
        
        // Step 2: Fill intent at manipulated (worse for user) price
        uint256 inflatedPrice = oracle.getRate();
        uint256 minOut = 1; // Fill at absolute minimum
        
        // Step 3: The fill uses the manipulated oracle price
        // User gets minimum while solver extracted the surplus
        
        // Step 4: Reverse price manipulation
        oracle.swap(manipulateAmount, false); // Push price back
        
        // Profit = price_manipulation_surplus - gas_costs
    }
}
