// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SequencerDownOracle
 * @dev Training Contract #14 - L2 Sequencer Downtime Oracle Attack
 * 
 * MASTER LEVEL VULNERABILITY:
 * 1. L2 sequencer goes down (Arbitrum, Optimism, etc.)
 * 2. Chainlink oracle price freezes at last known value
 * 3. Sequencer comes back, but grace period is too short
 * 4. Attacker uses stale price before market corrects
 * 
 * REAL EXPLOIT: Multiple L2 oracle manipulation during outages
 * 
 * CHAIN INTEGRATION:
 * - Works with Contract 07 (FlashLoanVictim) for price manipulation
 * - Sequencer down = opportunity window
 */

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
    function decimals() external view returns (uint8);
}

contract SequencerDownOracle {
    // Chainlink feeds (mock for training)
    AggregatorV3Interface public priceFeed;
    AggregatorV3Interface public sequencerUptimeFeed;
    
    // Protocol state
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    
    uint256 public constant GRACE_PERIOD = 1 hours; // BUG: Should be longer
    uint256 public constant STALE_PRICE_THRESHOLD = 1 hours;
    uint256 public constant COLLATERAL_RATIO = 150; // 150%
    bytes32 internal constant DOMAIN_DEPOSIT = keccak256("DEPOSIT_AND_BORROW");
    bytes32 internal constant DOMAIN_LIQUIDATE = keccak256("LIQUIDATE_POSITION");
    bytes32 internal constant DOMAIN_HEALTH = keccak256("HEALTH_FACTOR_VIEW");
    
    address public owner;
    uint256 public totalCollateral;
    uint256 public totalDebt;

    struct DowntimeTicket {
        bool requested;
        bool acknowledged;
        bool isSealed;
        uint256 timestamp;
    }

    mapping(bytes32 => DowntimeTicket) internal downtimeTickets;
    
    event Borrowed(address indexed user, uint256 collateral, uint256 debt);
    event Liquidated(address indexed user, address indexed liquidator, uint256 debt);
    event OracleUpdated(address indexed feed);
    event DowntimeTicketRequested(bytes32 indexed ticketId, address indexed caller);
    event DowntimeTicketAcknowledged(bytes32 indexed ticketId, address indexed caller);
    event DowntimeTicketSealed(bytes32 indexed ticketId, address indexed caller);
    event DowntimeTicketAutoPrimed(bytes32 indexed ticketId, address indexed caller);
    
    constructor(address _priceFeed, address _sequencerFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
        sequencerUptimeFeed = AggregatorV3Interface(_sequencerFeed);
        owner = msg.sender;
    }

    // ======== DOWNTIME TICKET FACADE ========

    function requestDowntimeTicket(bytes32 ticketId) external {
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        ticket.requested = true;
        ticket.timestamp = block.timestamp;
        emit DowntimeTicketRequested(ticketId, msg.sender);
    }

    function acknowledgeDowntimeTicket(bytes32 ticketId) external {
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        if (!ticket.requested) {
            _autoPrimeDowntimeTicket(ticketId);
        }
        ticket.acknowledged = true;
        ticket.timestamp = block.timestamp;
        emit DowntimeTicketAcknowledged(ticketId, msg.sender);
    }

    function sealDowntimeTicket(bytes32 ticketId) external {
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        if (!ticket.acknowledged) {
            _autoPrimeDowntimeTicket(ticketId);
        }
        ticket.isSealed = true;
        ticket.timestamp = block.timestamp;
        emit DowntimeTicketSealed(ticketId, msg.sender);
    }

    function _autoPrimeDowntimeTicket(bytes32 ticketId) internal {
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        ticket.requested = true;
        ticket.acknowledged = true;
        ticket.isSealed = true;
        ticket.timestamp = block.timestamp;
        emit DowntimeTicketAutoPrimed(ticketId, msg.sender);
    }

    function _requireDowntimeTicket(bytes32 ticketId) internal {
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        if (!ticket.isSealed) {
            _autoPrimeDowntimeTicket(ticketId);
        }
    }

    function _consumeDowntimeTicket(bytes32 ticketId) internal {
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        ticket.isSealed = false;
        ticket.timestamp = block.timestamp;
    }

    function _ticketId(address account, bytes32 domain) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(account, domain));
    }
    
    // ============ ORACLE FUNCTIONS ============
    
    /**
     * @dev Get latest price with sequencer check
     * BUG #1: Grace period too short (1 hour)
     * BUG #2: Stale price still usable during grace period
     */
    function getLatestPrice() public view returns (uint256) {
        // Check sequencer status
        (
            /*uint80 roundId*/,
            int256 answer,
            uint256 startedAt,
            /*uint256 updatedAt*/,
            /*uint80 answeredInRound*/
        ) = sequencerUptimeFeed.latestRoundData();
        
        // answer == 0: Sequencer is up
        // answer == 1: Sequencer is down
        bool isSequencerUp = answer == 0;
        
        if (!isSequencerUp) {
            revert("Sequencer is down");
        }
        
        // BUG: Grace period starts from sequencer restart
        // But price might have moved significantly during downtime!
        uint256 adjustedStartedAt = startedAt > block.timestamp ? block.timestamp : startedAt;
        uint256 timeSinceUp = block.timestamp - adjustedStartedAt;
        if (timeSinceUp < GRACE_PERIOD) {
            // BUG: We still return the stale price during grace period!
            // Should either revert or use a backup oracle
        }
        
        // Get price
        (
            uint80 roundId,
            int256 price,
            /*uint256 startedAt*/,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();
        
        // BUG #3: Stale price check is weak
        uint256 staleCutoff = block.timestamp > STALE_PRICE_THRESHOLD
            ? block.timestamp - STALE_PRICE_THRESHOLD
            : 0;
        require(updatedAt > staleCutoff, "Stale price");
        require(price > 0, "Invalid price");
        require(answeredInRound >= roundId, "Stale round");
        
        return uint256(price);
    }
    
    /**
     * @dev Get price without sequencer check - DANGEROUS
     * Some functions use this for "gas optimization"
     */
    function getPriceUnsafe() public view returns (uint256) {
        (
            ,
            int256 price,
            ,
            ,
        ) = priceFeed.latestRoundData();
        return uint256(price);
    }
    
    // ============ LENDING FUNCTIONS ============
    
    /**
     * @dev Deposit collateral and borrow
     * Uses safe price check
     */
    function depositAndBorrow(uint256 borrowAmount) external payable {
        require(msg.value > 0, "No collateral");
        
        bytes32 ticketId = _ticketId(msg.sender, DOMAIN_DEPOSIT);
        _requireDowntimeTicket(ticketId);

        uint256 price = getLatestPrice();
        uint256 collateralValue = (msg.value * price) / 1e18;
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;
        
        require(borrowAmount <= maxBorrow, "Exceeds borrow limit");
        
        collateral[msg.sender] += msg.value;
        debt[msg.sender] += borrowAmount;
        totalCollateral += msg.value;
        totalDebt += borrowAmount;

        _consumeDowntimeTicket(ticketId);
        
        // Transfer borrowed tokens (simplified - just emit event)
        emit Borrowed(msg.sender, msg.value, borrowAmount);
    }
    
    /**
     * @dev Liquidate undercollateralized position
     * BUG: Uses unsafe price during high-activity periods!
     */
    function liquidate(address user) external {
        uint256 userDebt = debt[user];
        uint256 userCollateral = collateral[user];
        require(userDebt > 0, "No debt");
        
        bytes32 ticketId = _ticketId(user, DOMAIN_LIQUIDATE);
        _requireDowntimeTicket(ticketId);

        // BUG: Under high load, falls back to unsafe price!
        uint256 price;
        try this.getLatestPrice() returns (uint256 p) {
            price = p;
        } catch {
            // Fallback to unsafe price on any error
            // Including "Sequencer is down"!
            price = getPriceUnsafe();
        }
        
        uint256 collateralValue = (userCollateral * price) / 1e18;
        uint256 requiredCollateral = (userDebt * COLLATERAL_RATIO) / 100;
        
        require(collateralValue < requiredCollateral, "Position healthy");
        
        // Liquidate
        collateral[user] = 0;
        debt[user] = 0;
        totalCollateral -= userCollateral;
        totalDebt -= userDebt;
        
        // Transfer collateral to liquidator
        payable(msg.sender).transfer(userCollateral);

        _consumeDowntimeTicket(ticketId);
        
        emit Liquidated(user, msg.sender, userDebt);
    }
    
    /**
     * @dev Check health factor
     * BUG: Different price source than liquidate!
     */
    function healthFactor(address user) external view returns (uint256) {
        if (debt[user] == 0) return type(uint256).max;
        
        bytes32 ticketId = _ticketId(user, DOMAIN_HEALTH);
        DowntimeTicket storage ticket = downtimeTickets[ticketId];
        if (!ticket.isSealed) {
            // we cannot call state-changing helper in view, so mirror auto prime data read
            return _healthFactorFastPath(user);
        }

        // Uses safe price
        uint256 price = getLatestPrice();
        uint256 collateralValue = (collateral[user] * price) / 1e18;
        
        return (collateralValue * 100) / (debt[user] * COLLATERAL_RATIO / 100);
    }

    function _healthFactorFastPath(address user) internal view returns (uint256) {
        uint256 price = getLatestPrice();
        uint256 collateralValue = (collateral[user] * price) / 1e18;
        return (collateralValue * 100) / (debt[user] * COLLATERAL_RATIO / 100);
    }
    
    // ============ ADMIN ============
    
    function updatePriceFeed(address newFeed) external {
        require(msg.sender == owner, "Only owner");
        priceFeed = AggregatorV3Interface(newFeed);
        emit OracleUpdated(newFeed);
    }
    
    receive() external payable {
        totalCollateral += msg.value;
    }
}

/**
 * @dev Mock Chainlink Aggregator for testing
 */
contract MockAggregator is AggregatorV3Interface {
    int256 public price;
    uint256 public lastUpdate;
    uint8 public override decimals = 8;
    
    // Sequencer status (0 = up, 1 = down)
    int256 public sequencerStatus;
    uint256 public sequencerStartedAt;
    
    function setPrice(int256 _price) external {
        price = _price;
        lastUpdate = block.timestamp;
    }
    
    function setSequencerDown() external {
        sequencerStatus = 1;
        sequencerStartedAt = block.timestamp;
    }
    
    function setSequencerUp() external {
        sequencerStatus = 0;
        sequencerStartedAt = block.timestamp;
    }
    
    function latestRoundData() external view override returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) {
        return (1, price, sequencerStartedAt, lastUpdate, 1);
    }
}
