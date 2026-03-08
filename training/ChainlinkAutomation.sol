// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ChainlinkAutomation
 * @dev Training Contract #54 - Chainlink Automation (Keepers) & CCIP Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. checkUpkeep Gas Bomb (AUTO-GASCHECK-01)
 * 2. performUpkeep Reentrancy (AUTO-PERFORM-REENTER-01)
 * 3. Upkeep Manipulation via State (AUTO-STATEMANIP-01)
 * 4. Log Trigger Spoof (AUTO-LOGTRIGGER-01)
 * 5. Conditional Upkeep Front-run (AUTO-FRONTRUN-01)
 * 6. Forwarder Address Trust (AUTO-FORWARDER-01)
 * 7. Upkeep Funding Drain (AUTO-FUNDRAIN-01)
 * 8. CCIP Message Replay (AUTO-CCIP-REPLAY-01)
 * 9. CCIP Token Pool Drain (AUTO-CCIP-POOL-01)
 * 10. CCIP Rate Limit Bypass (AUTO-CCIP-RATE-01)
 * 11. CCIP Router Trust Assumption (AUTO-CCIP-ROUTER-01)
 * 12. Functions Callback Manipulation (AUTO-FUNC-CALLBACK-01)
 * 13. VRF Subscription Drain (AUTO-VRF-DRAIN-01)
 * 14. Data Feed Deviation Exploit (AUTO-FEED-DEVIATE-01)
 * 15. Automation Registry Gaming (AUTO-REGISTRY-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): AUTO-*, chainlink, keeper, upkeep
 * - Engine 2 (deep-semantic): gas estimation, callback logic
 * - Engine 5 (reentrancy-checker): performUpkeep reentrancy
 * - Engine 4 (temporal-analyzer): staleness, timing attacks
 */

interface AutomationCompatibleInterface {
    function checkUpkeep(bytes calldata checkData) external returns (bool upkeepNeeded, bytes memory performData);
    function performUpkeep(bytes calldata performData) external;
}

interface IRouter {
    struct EVM2AnyMessage {
        bytes receiver;
        bytes data;
        address[] tokenAmounts;
        address feeToken;
        bytes extraArgs;
    }
    function ccipSend(uint64 destinationChainSelector, EVM2AnyMessage calldata message) external payable returns (bytes32);
}

interface IAny2EVMMessageReceiver {
    struct Any2EVMMessage {
        bytes32 messageId;
        uint64 sourceChainSelector;
        bytes sender;
        bytes data;
        address[] destTokenAmounts;
    }
    function ccipReceive(Any2EVMMessage calldata message) external;
}

// ========== VULN 1: checkUpkeep Gas Bomb (AUTO-GASCHECK-01) ==========
// ========== VULN 2: performUpkeep Reentrancy (AUTO-PERFORM-REENTER-01) ==========

contract VulnerableAutomation is AutomationCompatibleInterface {
    address public owner;
    address public forwarder; // Chainlink forwarder
    uint256 public counter;
    uint256 public lastPerform;
    mapping(address => uint256) public balances;
    bool private locked;

    // Log trigger state
    mapping(bytes32 => bool) public processedLogs;

    // CCIP state
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public tokenPoolBalances;
    mapping(uint64 => uint256) public rateLimitBuckets;
    mapping(uint64 => uint256) public rateLimitLastUpdate;
    address public ccipRouter;

    // VRF
    mapping(uint256 => address) public vrfRequesters;
    mapping(address => uint256) public vrfSubscriptions;

    // Price feed
    mapping(address => int256) public lastFeedPrice;
    mapping(address => uint256) public lastFeedUpdate;
    uint256 public maxDeviation = 500; // 5%

    // Registry
    mapping(uint256 => address) public upkeepOwners;
    mapping(uint256 => uint256) public upkeepBalances;
    uint256 public minBalance = 0.1 ether;

    constructor(address _router) {
        owner = msg.sender;
        ccipRouter = _router;
    }

    // BUG #1: checkUpkeep does unbounded computation
    // Chainlink node calls this with limited gas—if it OOGs, upkeep never triggers
    function checkUpkeep(bytes calldata checkData) 
        external override returns (bool upkeepNeeded, bytes memory performData) 
    {
        // VULN: unbounded loop in checkUpkeep can consume all gas
        // attacker inflates pendingItems array, DOSing the upkeep
        uint256 sum = 0;
        uint256 iterations = abi.decode(checkData, (uint256));
        for (uint256 i = 0; i < iterations; i++) {
            sum += i * i; // expensive computation
        }
        upkeepNeeded = (block.timestamp - lastPerform > 60);
        performData = abi.encode(sum);
    }

    // BUG #2: performUpkeep can be re-entered via external call
    function performUpkeep(bytes calldata performData) external override {
        require(msg.sender == forwarder || msg.sender == owner, "not authorized");
        // VULN: no reentrancy guard, external call before state update
        counter++;
        
        // External call to process result
        (bool ok, ) = msg.sender.call(abi.encode(counter));
        // Re-entrant call can invoke performUpkeep again
        
        lastPerform = block.timestamp;
    }

    // ========== VULN 3: Upkeep Manipulation via State (AUTO-STATEMANIP-01) ==========

    // BUG #3: state that triggers upkeep can be manipulated to force/prevent execution
    function manipulateState(uint256 newTimestamp) external {
        // VULN: no access control on state that checkUpkeep reads
        lastPerform = newTimestamp; // advance to prevent upkeep
        // attacker prevents critical liquidations by keeping upkeep "current"
    }

    // ========== VULN 4: Log Trigger Spoof (AUTO-LOGTRIGGER-01) ==========

    event UpkeepTrigger(address indexed sender, uint256 amount);

    // BUG #4: anyone can emit the trigger event to force upkeep execution
    function spoofLogTrigger(uint256 amount) external {
        // VULN: no restriction on who can emit trigger event
        // attacker emits millions of events, draining upkeep LINK balance
        emit UpkeepTrigger(msg.sender, amount);
    }

    // ========== VULN 5: Conditional Upkeep Front-run (AUTO-FRONTRUN-01) ==========

    // BUG #5: upkeep execution visible in mempool
    // attacker front-runs the performUpkeep to extract value
    function performLiquidation(bytes calldata performData) external {
        (address target, uint256 amount) = abi.decode(performData, (address, uint256));
        // VULN: liquidation params visible in pending tx
        // MEV bot front-runs with own liquidation call
        balances[target] -= amount;
        balances[msg.sender] += amount / 10; // reward
    }

    // ========== VULN 6: Forwarder Address Trust (AUTO-FORWARDER-01) ==========

    // BUG #6: forwarder can be changed without timelock
    function setForwarder(address _forwarder) external {
        require(msg.sender == owner);
        // VULN: owner can set any address as forwarder
        // compromised owner sets attacker as forwarder, calls performUpkeep
        forwarder = _forwarder;
    }

    // ========== VULN 7: Upkeep Funding Drain (AUTO-FUNDRAIN-01) ==========

    // BUG #7: each performUpkeep costs LINK, attacker triggers unnecessary upkeeps
    function triggerExpensiveUpkeep() external {
        // VULN: expensive operation that consumes lots of gas on each perform
        // attacker front-runs to ensure checkUpkeep returns true frequently
        // draining the LINK balance of the upkeep
        for (uint256 i = 0; i < 100; i++) {
            balances[address(uint160(i))] = i; // storage writes = expensive gas
        }
    }

    // ========== VULN 8: CCIP Message Replay (AUTO-CCIP-REPLAY-01) ==========

    // BUG #8: CCIP message processed without proper dedup
    function ccipReceive(IAny2EVMMessageReceiver.Any2EVMMessage calldata message) external {
        require(msg.sender == ccipRouter, "not router");
        // VULN: messageId check can be bypassed if same payload sent with new messageId
        processedMessages[message.messageId] = true;
        // No payload hash dedup—same content, new ID = double-mint
        (address to, uint256 amount) = abi.decode(message.data, (address, uint256));
        balances[to] += amount;
    }

    // ========== VULN 9: CCIP Token Pool Drain (AUTO-CCIP-POOL-01) ==========

    // BUG #9: token pool release without verifying source chain burn
    function releaseFromPool(address token, address to, uint256 amount) external {
        require(msg.sender == ccipRouter, "not router");
        // VULN: trusts router completely, if router is compromised
        // or source chain lock/burn didn't actually happen
        // tokens released from pool without backing
        tokenPoolBalances[token] -= amount;
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok);
    }

    // ========== VULN 10: CCIP Rate Limit Bypass (AUTO-CCIP-RATE-01) ==========

    // BUG #10: rate limit uses token bucket, but bucket refill is gameable
    function checkRateLimit(uint64 chainSelector, uint256 amount) external returns (bool) {
        uint256 elapsed = block.timestamp - rateLimitLastUpdate[chainSelector];
        // VULN: rate limit refills continuously, attacker sends many small messages
        // that individually pass but collectively exceed intended rate
        rateLimitBuckets[chainSelector] += elapsed * 100; // refill rate
        rateLimitLastUpdate[chainSelector] = block.timestamp;
        
        if (rateLimitBuckets[chainSelector] >= amount) {
            rateLimitBuckets[chainSelector] -= amount;
            return true;
        }
        return false;
    }

    // ========== VULN 11: CCIP Router Trust Assumption (AUTO-CCIP-ROUTER-01) ==========

    // BUG #11: any function checking msg.sender == ccipRouter is vulnerable
    // if router is upgraded/replaced, old receiver still trusts old router
    function updateRouter(address newRouter) external {
        require(msg.sender == owner);
        // VULN: changing router breaks in-flight messages from old router
        // AND: old router address may still be trusted elsewhere
        ccipRouter = newRouter;
    }

    // ========== VULN 12: Functions Callback Manipulation (AUTO-FUNC-CALLBACK-01) ==========

    mapping(bytes32 => bytes) public pendingRequests;

    // BUG #12: Chainlink Functions callback data is user-controlled JavaScript result
    function fulfillRequest(bytes32 requestId, bytes calldata response, bytes calldata err) external {
        require(msg.sender == ccipRouter, "not router"); // simplified
        // VULN: response could be manipulated by DON consensus attack
        // or JavaScript source could have hidden logic
        if (err.length == 0) {
            uint256 price = abi.decode(response, (uint256));
            // Using manipulated price for critical business logic
            lastFeedPrice[address(0)] = int256(price);
        }
    }

    // ========== VULN 13: VRF Subscription Drain (AUTO-VRF-DRAIN-01) ==========

    // BUG #13: VRF consumer can request unlimited random numbers
    // each request costs LINK from subscription
    function requestRandomness() external returns (uint256 requestId) {
        // VULN: no per-consumer rate limit or spending cap
        // malicious consumer drains shared VRF subscription
        requestId = uint256(keccak256(abi.encode(block.timestamp, msg.sender)));
        vrfRequesters[requestId] = msg.sender;
        // Each call costs LINK from subscription
    }

    // ========== VULN 14: Data Feed Deviation Exploit (AUTO-FEED-DEVIATE-01) ==========

    // BUG #14: price feed with deviation threshold allows manipulation within band
    function updateFeedPrice(address feed, int256 newPrice) external {
        int256 oldPrice = lastFeedPrice[feed];
        uint256 deviation;
        if (oldPrice > 0) {
            deviation = uint256((newPrice - oldPrice) * 10000 / oldPrice);
            if (deviation < 0) deviation = uint256((-int256(deviation)));
        }
        // VULN: price can be slowly walked within deviation threshold
        // each update < 5% deviation, but over multiple updates = massive drift
        require(deviation <= maxDeviation || oldPrice == 0, "deviation too high");
        lastFeedPrice[feed] = newPrice;
        lastFeedUpdate[feed] = block.timestamp;
    }

    // ========== VULN 15: Automation Registry Gaming (AUTO-REGISTRY-01) ==========

    // BUG #15: upkeep registration with minimal balance, consuming shared resources
    function registerUpkeep(uint256 upkeepId) external payable {
        require(msg.value >= minBalance, "insufficient balance");
        // VULN: minimum balance too low, attacker registers many upkeeps
        // consuming Chainlink DON computational resources
        upkeepOwners[upkeepId] = msg.sender;
        upkeepBalances[upkeepId] = msg.value;
    }

    function cancelUpkeep(uint256 upkeepId) external {
        require(upkeepOwners[upkeepId] == msg.sender, "not owner");
        uint256 refund = upkeepBalances[upkeepId];
        upkeepBalances[upkeepId] = 0;
        // VULN: instant refund, no penalty for spam registration
        payable(msg.sender).transfer(refund);
    }

    receive() external payable {}
}
