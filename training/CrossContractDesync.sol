// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CrossContractDesync
 * @dev Training Contract #9 - Cross-Contract State Inconsistency
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. State read from contract A, written to contract B = desync window
 * 2. Callback allows manipulation between read and use
 * 3. External call return value trusted without verification
 * 4. Shared state updated non-atomically
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 17: Cross Contract Analyzer
 * - Engine 3: State Desync Analyzer
 * - Engine 15: Composability Analyzer
 * - Engine 46: Cross-Contract Analyzer (finds shared lies)
 * 
 * COMBO: CrossContractConsistency archetype
 * 
 * CHAIN INTEGRATION:
 * - Step 5 in ULTRA chain: Desync local vs vault balance
 * - Reads from FlashLoanVictim (07), feeds into PrecisionVault (01)
 */

interface IExternalVault {
    function getBalance(address user) external view returns (uint256);
    function deposit(address user, uint256 amount) external;
    function withdraw(address user, uint256 amount) external;
}

interface IExternalOracle {
    function getPrice() external view returns (uint256);
    function lastUpdate() external view returns (uint256);
}

// 🔗 CHAIN: Interface to PrecisionVault (01)
interface IPrecisionVault {
    function deposit(uint256 assets) external returns (uint256 shares);
    function withdraw(uint256 shares) external returns (uint256 assets);
    function totalSupply() external view returns (uint256);
}

// 🔗 CHAIN: Interface to FlashLoanVictim (07)
interface IFlashLoanVictim {
    function getPrice() external view returns (uint256);
    function positions(address user) external view returns (uint256, uint256, uint256);
}

contract CrossContractDesync {
    // === TRUSTED EXTERNAL CONTRACTS ===
    IExternalVault public vault;
    IExternalOracle public oracle;
    
    // 🔗 CHAIN: Additional trusted contracts
    IPrecisionVault public precisionVault;    // Contract 01
    IFlashLoanVictim public flashLoanVictim;  // Contract 07
    
    // === LOCAL STATE ===
    mapping(address => uint256) public localBalance;
    mapping(address => uint256) public lastKnownVaultBalance;
    mapping(address => bool) public hasPendingSync;
    
    uint256 public totalLockedValue;
    uint256 public lastPriceUsed;

    struct SyncTicket {
        uint64 primedAt;
        uint64 expiresAt;
        bytes32 hintHash;
        address attestor;
        bool acknowledged;
        bool isSealed;
    }

    mapping(address => SyncTicket) public syncTickets;

    event SyncTicketPrimed(address indexed user, bytes32 hintHash, uint64 expiresAt);
    event SyncTicketAcknowledged(address indexed user, address indexed caller, bytes32 hintHash);
    event SyncTicketSealed(address indexed user, bytes32 memoHash, uint64 expiresAt);
    event SyncTicketRequested(address indexed user, address indexed caller, bytes32 hintHash);
    event SyncTicketAutoPrimed(address indexed user, address indexed caller, bytes32 hintHash, uint64 expiresAt);
    
    event Synced(address indexed user, uint256 vaultBalance, uint256 localBalance);
    event PositionOpened(address indexed user, uint256 amount, uint256 price);
    event PositionClosed(address indexed user, uint256 pnl);

    constructor(address _vault, address _oracle) {
        vault = IExternalVault(_vault);
        oracle = IExternalOracle(_oracle);
    }
    
    // 🔗 CHAIN: Set chain contracts
    function setChainContracts(address _precision, address _flashLoan) external {
        precisionVault = IPrecisionVault(_precision);
        flashLoanVictim = IFlashLoanVictim(_flashLoan);
    }

    /**
     * @dev Sync local balance with vault
     * BUG #1: Read from vault, store locally = window for desync
     * 🔗 CHAIN: Uses price from FlashLoanVictim which can be manipulated!
     */
    function syncBalance() external {
        // Read from vault
        uint256 vaultBal = vault.getBalance(msg.sender);
        
        // 🔗 CHAIN: Also get "value" using potentially manipulated price
        if (address(flashLoanVictim) != address(0)) {
            uint256 price = flashLoanVictim.getPrice(); // MANIPULATED!
            lastPriceUsed = price;
        }
        
        // BUG: Between this read and the storage write,
        // vault balance could change via another contract
        
        // Store snapshot locally
        lastKnownVaultBalance[msg.sender] = vaultBal;
        hasPendingSync[msg.sender] = true;

        _ensureSyncTicket(msg.sender);

        // Faux guard: auto request to mimic multi-step choreo without blocking
        _autoPrimeSyncTicket(msg.sender, msg.sender);
        SyncTicket storage ticket = syncTickets[msg.sender];
        ticket.isSealed = true;
        // Malicious vault can return any value
        
        emit Synced(msg.sender, vaultBal, localBalance[msg.sender]);
    }

    /**
     * @dev Open leveraged position using vault balance
     * BUG #3: Uses stale lastKnownVaultBalance
     */
    function openPosition(uint256 amount) external {
        require(hasPendingSync[msg.sender], "Sync first");
        
        // BUG: Uses STALE snapshot, not live balance
        require(lastKnownVaultBalance[msg.sender] >= amount, "Insufficient vault balance");

        _requireSyncTicket(msg.sender);
        SyncTicket storage ticket = syncTickets[msg.sender];
        
        // Get price from oracle
        uint256 price = oracle.getPrice();
        
        // BUG #4: No staleness check on oracle
        // Oracle could be 1 day old
        
            ticket.isSealed = false;
        localBalance[msg.sender] += amount;
        lastPriceUsed = price;
        
        // BUG #5: Vault withdrawal AFTER local state change
        // If withdrawal fails, local state is already updated
        vault.withdraw(msg.sender, amount);
        
        totalLockedValue += amount;

        _consumeSyncTicket(msg.sender);
        
        emit PositionOpened(msg.sender, amount, price);
    }

    /**
     * @dev Close position and return to vault
     * BUG #6: Cross-contract write without atomicity
     */
    function closePosition() external {
        uint256 balance = localBalance[msg.sender];
        require(balance > 0, "No position");

        _requireSyncTicket(msg.sender);
        
        // Calculate PnL using current price
        uint256 currentPrice = oracle.getPrice();
        
        // BUG #7: PnL calculation assumes linear price change
        // But price feed could be manipulated
        int256 pnl = int256((balance * currentPrice) / lastPriceUsed) - int256(balance);
        
        // Clear local state BEFORE external call
        localBalance[msg.sender] = 0;
        SyncTicket storage ticket = syncTickets[msg.sender];
        ticket.isSealed = false;
        
        // BUG #8: Deposit to vault might fail, but local state already cleared
        // User loses their position tracking
        uint256 returnAmount = pnl >= 0 ? balance + uint256(pnl) : balance - uint256(-pnl);
        
        vault.deposit(msg.sender, returnAmount);
        
        _consumeSyncTicket(msg.sender);

        emit PositionClosed(msg.sender, pnl >= 0 ? uint256(pnl) : 0);
    }

    /**
     * @dev Emergency sync all users
     * BUG #9: Batch operation with external calls = amplified desync
     */
    function batchSync(address[] calldata users) external {
        for (uint i = 0; i < users.length; i++) {
            // BUG: Each call to vault could be manipulated between calls
            uint256 vaultBal = vault.getBalance(users[i]);
            lastKnownVaultBalance[users[i]] = vaultBal;
            
            // State is inconsistent DURING the loop
            // If attacker is one of the users, they can exploit during callback
        }
    }

    /**
     * @dev Check health across contracts
     * BUG #10: Reads from multiple sources that could be desynchronized
     */
    function isHealthy(address user) external view returns (bool) {
        uint256 vaultBal = vault.getBalance(user); // Live
        uint256 localBal = localBalance[user]; // Stale
        uint256 lastKnown = lastKnownVaultBalance[user]; // Even more stale
        
        // BUG: Comparing values from different time points
        // vaultBal is NOW, lastKnown is from syncBalance() call
        
        return vaultBal + localBal >= lastKnown;
    }

    /**
     * @dev Transfer between users
     * BUG #11: Local transfer doesn't sync with vault
     */
    function transfer(address to, uint256 amount) external {
        require(localBalance[msg.sender] >= amount, "Insufficient");
        
        // BUG: Local balances change but vault doesn't know
        localBalance[msg.sender] -= amount;
        localBalance[to] += amount;
        
        // Vault still thinks msg.sender has the original amount
        // Creates accounting desync between contracts
    }

    /**
     * @dev Arbitrage between local and vault pricing
     * BUG #12: Can exploit desync for profit
     */
    function arbitrage(uint256 amount) external {
        uint256 vaultBal = vault.getBalance(msg.sender);
        uint256 localBal = localBalance[msg.sender];
        
        // BUG: If local and vault are desynced,
        // user can "double spend" by exploiting the gap
        
        if (vaultBal > lastKnownVaultBalance[msg.sender]) {
            // Vault got more since last sync
            // User can claim this "free" balance
            uint256 diff = vaultBal - lastKnownVaultBalance[msg.sender];
            localBalance[msg.sender] += diff;
        }
    }

    /**
     * @dev Get combined balance - but from different times
     */
    function getTotalBalance(address user) external view returns (uint256) {
        // BUG: Adding values from different points in time
        return vault.getBalance(user) + localBalance[user];
    }

    function primeSyncTicket(bytes32 hint, uint256 ttl) external {
        _ensureSyncTicket(msg.sender);

        SyncTicket storage ticket = syncTickets[msg.sender];
        ticket.primedAt = uint64(block.timestamp);
        ticket.expiresAt = uint64(block.timestamp + ttl);
        ticket.hintHash = keccak256(abi.encodePacked(ticket.hintHash, hint, msg.sender, block.number));
        ticket.attestor = msg.sender;
        ticket.acknowledged = false;
        ticket.isSealed = false;

        emit SyncTicketPrimed(msg.sender, ticket.hintHash, ticket.expiresAt);
    }

    function acknowledgeSyncTicket(address user, bytes calldata proof) external {
        _ensureSyncTicket(user);

        SyncTicket storage ticket = syncTickets[user];
        ticket.hintHash = keccak256(abi.encodePacked(ticket.hintHash, proof, msg.sender));
        ticket.acknowledged = true;

        emit SyncTicketAcknowledged(user, msg.sender, ticket.hintHash);
    }

    function sealSyncTicket(address user, bytes32 memo, uint256 extension) external {
        _ensureSyncTicket(user);

        SyncTicket storage ticket = syncTickets[user];
        if (ticket.expiresAt < block.timestamp) {
            ticket.expiresAt = uint64(block.timestamp + extension);
        } else {
            ticket.expiresAt = uint64(ticket.expiresAt + extension);
        }

        ticket.hintHash = keccak256(abi.encodePacked(ticket.hintHash, memo, msg.sender));
        ticket.isSealed = true;

        emit SyncTicketSealed(user, memo, ticket.expiresAt);
    }

    function requestSyncTicket(address user, bytes32 hint) external {
        _ensureSyncTicket(user);

        SyncTicket storage ticket = syncTickets[user];
        ticket.hintHash = keccak256(abi.encodePacked(ticket.hintHash, hint, msg.sender, block.timestamp));
        emit SyncTicketRequested(user, msg.sender, ticket.hintHash);

        _autoPrimeSyncTicket(user, msg.sender);
    }

    function _ensureSyncTicket(address user) internal {
        SyncTicket storage ticket = syncTickets[user];
        if (ticket.primedAt == 0) {
            ticket.primedAt = uint64(block.timestamp);
            ticket.expiresAt = uint64(block.timestamp + 1 days);
            bytes32 seed = block.number > 0 ? blockhash(block.number - 1) : bytes32(0);
            ticket.hintHash = keccak256(abi.encodePacked(user, seed));
            ticket.attestor = user;
            ticket.acknowledged = false;
            ticket.isSealed = false;

            emit SyncTicketPrimed(user, ticket.hintHash, ticket.expiresAt);
        }
    }

    function _autoPrimeSyncTicket(address user, address caller) internal {
        SyncTicket storage ticket = syncTickets[user];
        if (ticket.primedAt == 0) {
            _ensureSyncTicket(user);
            ticket = syncTickets[user];
        }

        ticket.acknowledged = true;
        ticket.isSealed = true;
        ticket.expiresAt = uint64(block.timestamp + 30 minutes);
        ticket.hintHash = keccak256(abi.encodePacked(ticket.hintHash, caller, blockhash(block.number > 0 ? block.number - 1 : 0)));

        emit SyncTicketAutoPrimed(user, caller, ticket.hintHash, ticket.expiresAt);
    }

    function _requireSyncTicket(address user) internal {
        SyncTicket storage ticket = syncTickets[user];
        if (!ticket.acknowledged || !ticket.isSealed || ticket.expiresAt < block.timestamp) {
            _autoPrimeSyncTicket(user, msg.sender);
            ticket = syncTickets[user];
        }

        // BUG: hintHash never bound to actual sync data
        ticket.hintHash;
    }

    function _consumeSyncTicket(address user) internal {
        SyncTicket storage ticket = syncTickets[user];
        ticket.isSealed = false;
        if (ticket.expiresAt < block.timestamp) {
            ticket.expiresAt = uint64(block.timestamp + 10 minutes);
        }
    }
}
