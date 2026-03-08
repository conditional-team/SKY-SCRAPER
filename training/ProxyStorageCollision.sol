// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ProxyStorageCollision
 * @dev Training Contract #8 - Storage Layout + Proxy Vulnerabilities
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. Storage slot collision between proxy and implementation
 * 2. Uninitialized storage in upgraded implementation
 * 3. Function selector collision with proxy admin functions
 * 4. Delegatecall to untrusted implementation
 * 5. Immutable variables silently change on implementation upgrade
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 22: Storage Layout Analyzer
 * - Engine 21: Bleeding Edge (Proxy attacks)
 * - Engine 17: Cross Contract Analyzer
 * - Engine 37: EVM Disassembler (DELEGATECALL)
 * 
 * COMBO: A3 Upgrade/Config × Legacy State
 */

contract ProxyStorageCollision {
    // ========== PROXY STORAGE (slots 0-2) ==========
    
    // Slot 0: Implementation address
    address public implementation;
    
    // Slot 1: Admin address
    address public admin;
    
    // Slot 2: Upgrade pending
    bool public upgradePending;
    
    // ========== END PROXY STORAGE ==========
    
    event Upgraded(address indexed oldImpl, address indexed newImpl);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @dev Upgrade implementation
     * BUG #1: No storage layout validation
     */
    function upgrade(address newImplementation) external {
        require(msg.sender == admin, "Not admin");
        require(newImplementation != address(0), "Zero address");
        require(newImplementation.code.length > 0, "Not a contract");
        
        address oldImpl = implementation;
        implementation = newImplementation;
        
        // BUG: No check that new impl has compatible storage layout
        // New impl might use slot 0-2 for different data
        
        emit Upgraded(oldImpl, newImplementation);
    }

    /**
     * @dev Upgrade with initialization - but init might collide
     * BUG #2: initialize() in impl might overwrite proxy storage
     */
    function upgradeAndCall(address newImplementation, bytes calldata data) external {
        require(msg.sender == admin, "Not admin");
        
        address oldImpl = implementation;
        implementation = newImplementation;
        
        // BUG: Delegatecall to initialize might write to slot 0-2
        // If impl has: address public owner; // slot 0
        // It will overwrite our implementation address!
        (bool success, ) = newImplementation.delegatecall(data);
        require(success, "Init failed");
        
        emit Upgraded(oldImpl, newImplementation);
    }

    /**
     * @dev Change admin
     * BUG #3: Admin can be set to contract that auto-executes
     */
    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin, "Not admin");
        
        address oldAdmin = admin;
        admin = newAdmin;
        
        // BUG: No check if newAdmin is contract
        // Contract admin can have receive/fallback that calls back
        
        emit AdminChanged(oldAdmin, newAdmin);
    }

    /**
     * @dev Fallback - delegate all calls
     * BUG #4: Function selector collision with upgrade()
     */
    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "No implementation");
        
        // BUG #5: No check for admin functions being shadowed
        // If impl has function with same selector as upgrade(), it shadows
        // Selector collision: 0x3659cfe6 could match both
        
        assembly {
            // Copy calldata
            calldatacopy(0, 0, calldatasize())
            
            // Delegatecall to implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            
            // Copy returndata
            returndatacopy(0, 0, returndatasize())
            
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @title VulnerableImplementation
 * @dev Implementation with storage collision
 */
contract VulnerableImplementation {
    // ========== BUG: COLLIDES WITH PROXY STORAGE ==========
    
    // Slot 0: BUG - Collides with proxy.implementation
    address public owner;
    
    // Slot 1: BUG - Collides with proxy.admin
    uint256 public totalDeposits;
    
    // Slot 2: BUG - Collides with proxy.upgradePending
    mapping(address => uint256) public balances;
    
    // ========== END COLLISION ZONE ==========
    
    bool public initialized;
    
    // BUG #10: IMMUTABLE lives in BYTECODE, not in storage!
    // When proxy delegatecalls, the impl contract's bytecode runs
    // After upgrade to new impl (deployed with different constructor args),
    // these values SILENTLY change without any event or migration
    // Old impl: MAX_DEPOSIT=100 ether, TRUSTED_ORACLE=0xAAA
    // New impl: MAX_DEPOSIT=50 ether, TRUSTED_ORACLE=0xBBB
    // Protocol parameters mutate invisibly on upgrade
    uint256 public immutable MAX_DEPOSIT;
    address public immutable TRUSTED_ORACLE;
    uint256 public immutable DEPLOY_TIMESTAMP;
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event PriceUpdated(uint256 newPrice);

    constructor(uint256 _maxDeposit, address _trustedOracle) {
        MAX_DEPOSIT = _maxDeposit;
        TRUSTED_ORACLE = _trustedOracle;
        DEPLOY_TIMESTAMP = block.timestamp;
        // BUG: Should call _disableInitializers() here
        // Without it, anyone can call initialize() directly on impl contract
    }

    /**
     * @dev Initialize - BUG #6: Overwrites proxy storage
     */
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        
        // BUG: Writing to slot 0 = overwriting proxy.implementation
        owner = _owner;
        
        initialized = true;
    }

    /**
     * @dev Deposit funds
     */
    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        // BUG #10: MAX_DEPOSIT is immutable — silently changes on upgrade
        // Old impl allowed 100 ether, new impl allows 50 ether
        // Users who relied on old limit get unexpected reverts
        require(msg.value <= MAX_DEPOSIT, "Exceeds max deposit");
        
        balances[msg.sender] += msg.value;
        
        // BUG #7: Writing to slot 1 = overwriting proxy.admin
        totalDeposits += msg.value;
        
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @dev Withdraw funds
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        totalDeposits -= amount; // Still collides
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @dev BUG #8: Function with selector that might collide
     * Selector: upgrade(address) = 0x0900f010
     * This is different, but demonstrates the risk
     */
    function upgrade(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
        // If this had same selector as proxy's upgrade(),
        // proxy upgrade would be shadowed
    }

    /**
     * @dev Update price via trusted oracle
     * BUG #10: TRUSTED_ORACLE is immutable — changes on upgrade
     *   Before upgrade: TRUSTED_ORACLE = oracleA → only oracleA can call
     *   After upgrade:  TRUSTED_ORACLE = oracleB → oracleA locked out silently
     *   No event, no migration, oracle integration breaks without warning
     */
    uint256 public lastPrice;
    
    function updatePrice(uint256 newPrice) external {
        require(msg.sender == TRUSTED_ORACLE, "Not trusted oracle");
        require(block.timestamp >= DEPLOY_TIMESTAMP + 1 hours, "Too soon");
        lastPrice = newPrice;
        emit PriceUpdated(newPrice);
    }

    /**
     * @dev Owner withdraw all - BUG #9: owner is corrupted
     */
    function emergencyWithdraw() external {
        // BUG: owner (slot 0) was overwritten by proxy.implementation
        // So this check passes for whoever implementation address is
        require(msg.sender == owner, "Not owner");
        
        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @dev Get owner - returns corrupted value
     */
    function getOwner() external view returns (address) {
        return owner; // Returns proxy.implementation address!
    }
}

/**
 * @title SafeImplementation
 * @dev Shows correct pattern (for comparison)
 */
contract SafeImplementation {
    // ========== GAP TO AVOID COLLISION ==========
    
    // Slots 0-49 reserved for proxy
    uint256[50] private __gap;
    
    // ========== IMPLEMENTATION STORAGE STARTS AT SLOT 50 ==========
    
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;
    bool public initialized;
    
    // This is the SAFE pattern - but not what our vulnerable contract uses
}
