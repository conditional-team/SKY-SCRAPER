// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title GhostStateOracle
 * @dev Training Contract #3 - Ghost State + Cross-Contract Desync
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. Cached price vs live price divergence (ghost state)
 * 2. Oracle update doesn't propagate to dependent contracts
 * 3. Stale price check uses wrong comparison
 * 4. Multiple oracles can have conflicting "truths"
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 10: Ghost State Detector
 * - Engine 3: State Desync Analyzer
 * - Engine 17: Cross Contract Analyzer
 * - Engine 5: Economic Drift Detector
 * 
 * COMBO: C1 Ghost State × Cross-Contract
 */

interface IConsumer {
    function notifyPriceUpdate(uint256 newPrice) external;
}

contract GhostStateOracle {
    address public owner;
    address public keeper;
    
    // Primary price state
    uint256 public currentPrice;
    uint256 public lastUpdateTime;
    uint256 public constant MAX_STALENESS = 1 hours;
    
    // BUG #1: Cached price for "efficiency" - creates ghost state
    uint256 public cachedPrice;
    uint256 public cacheExpiry;
    uint256 public constant CACHE_DURATION = 5 minutes;
    
    // BUG #2: Historical prices - can be used to "prove" old states
    mapping(uint256 => uint256) public historicalPrices; // block => price
    
    // BUG #3: Consumer contracts that trust our price
    address[] public consumers;
    mapping(address => uint256) public consumerLastKnownPrice;
    
    // BUG #4: Competing source can set different "truth"
    mapping(address => bool) public trustedSources;
    mapping(address => uint256) public sourcePrice;
    
    event PriceUpdated(uint256 oldPrice, uint256 newPrice, address indexed source);
    event ConsumerRegistered(address indexed consumer);
    event CacheRefreshed(uint256 price, uint256 expiry);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier onlyKeeper() {
        require(msg.sender == keeper || msg.sender == owner, "Not keeper");
        _;
    }
    
    modifier onlyTrustedSource() {
        require(trustedSources[msg.sender] || msg.sender == keeper, "Not trusted");
        _;
    }

    constructor() {
        owner = msg.sender;
        keeper = msg.sender;
        currentPrice = 1e18; // Start at 1:1
        lastUpdateTime = block.timestamp;
        cachedPrice = currentPrice;
        cacheExpiry = block.timestamp + CACHE_DURATION;
    }

    /**
     * @dev Primary price update - keeper only
     * BUG #5: Updates currentPrice but NOT cachedPrice immediately
     */
    function updatePrice(uint256 newPrice) external onlyKeeper {
        require(newPrice > 0, "Invalid price");
        
        // Save to history
        historicalPrices[block.number] = currentPrice;
        
        uint256 oldPrice = currentPrice;
        currentPrice = newPrice;
        lastUpdateTime = block.timestamp;
        
        // BUG: Cache NOT updated here - ghost state exists until cache expires
        // For up to 5 minutes, cachedPrice != currentPrice
        
        emit PriceUpdated(oldPrice, newPrice, msg.sender);
        
        // BUG #6: Notify consumers with OLD cached price if still valid
        _notifyConsumers();
    }

    /**
     * @dev BUG #7: Consumers notified with potentially stale cached price
     */
    function _notifyConsumers() internal {
        uint256 priceToSend = getPrice(); // This might return cached!
        
        for (uint i = 0; i < consumers.length; i++) {
            // BUG: Store "last known" but it's the cached/ghost price
            consumerLastKnownPrice[consumers[i]] = priceToSend;
            
            try IConsumer(consumers[i]).notifyPriceUpdate(priceToSend) {
                // Success
            } catch {
                // BUG: Silent failure - consumer has stale price forever
            }
        }
    }

    /**
     * @dev Get price - returns cached if not expired
     * BUG #8: Cache can be 5 min stale, currentPrice could have moved 50%
     */
    function getPrice() public view returns (uint256) {
        if (block.timestamp < cacheExpiry) {
            return cachedPrice; // Returns GHOST state
        }
        return currentPrice;
    }

    /**
     * @dev Get "fresh" price - but still might be 1 hour stale
     * BUG #9: Staleness check wrong - allows exactly MAX_STALENESS
     */
    function getFreshPrice() external view returns (uint256) {
        require(
            block.timestamp <= lastUpdateTime + MAX_STALENESS, // BUG: <= not <
            "Price stale"
        );
        return currentPrice;
    }

    /**
     * @dev Refresh cache manually
     */
    function refreshCache() external {
        cachedPrice = currentPrice;
        cacheExpiry = block.timestamp + CACHE_DURATION;
        emit CacheRefreshed(cachedPrice, cacheExpiry);
    }

    /**
     * @dev BUG #10: Trusted source can set DIFFERENT price
     * This creates competing "truth" states
     */
    function submitSourcePrice(uint256 price) external onlyTrustedSource {
        sourcePrice[msg.sender] = price;
        
        // BUG: This doesn't update currentPrice, just stores source opinion
        // Consumer might query this source and get different answer
    }

    /**
     * @dev Get median from sources - but implementation is broken
     * BUG #11: Only uses first source, not actual median
     */
    function getMedianPrice() external view returns (uint256) {
        // BUG: Returns first source price, not median
        // If currentPrice = 100, sourcePrice[source1] = 200
        // This returns 200, not 150
        if (sourcePrice[keeper] > 0) {
            return sourcePrice[keeper];
        }
        return currentPrice;
    }

    /**
     * @dev Historical proof - can be used to "prove" favorable past price
     * BUG #12: Attacker can use old price in their favor
     */
    function proveHistoricalPrice(uint256 blockNumber) external view returns (uint256) {
        require(blockNumber < block.number, "Future block");
        return historicalPrices[blockNumber];
    }

    /**
     * @dev Consumer registration
     */
    function registerConsumer(address consumer) external onlyOwner {
        consumers.push(consumer);
        consumerLastKnownPrice[consumer] = getPrice(); // BUG: Cached/ghost
        emit ConsumerRegistered(consumer);
    }

    function addTrustedSource(address source) external onlyOwner {
        trustedSources[source] = true;
    }

    function setKeeper(address _keeper) external onlyOwner {
        keeper = _keeper;
    }
}
