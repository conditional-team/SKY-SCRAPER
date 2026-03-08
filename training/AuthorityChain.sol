// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AuthorityChain
 * @dev Training Contract #2 - Authority Chain + Emergent Privilege
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. Transitive admin permissions create emergent privilege
 * 2. Delegate can add other delegates, forming unlimited chain
 * 3. Revoked delegate retains historical permissions
 * 4. Time-delayed admin transfer can be frontrun
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 6: Authority Chain Mapper
 * - Engine 14: Emergent Privilege Finder
 * - Engine 11: Caller Myth Analyzer
 * - Engine 4: Temporal Analyzer
 * 
 * COMBO: A1 Authorization Drift × Timing
 * 
 * CHAIN INTEGRATION:
 * - Step 4 in ULTRA chain: Historical permissions allow unauthorized action
 * - Step 2+5 in COMPLEX chain: Grants trust to Create2Metamorphic deployed contracts
 */

// 🔗 CHAIN: Interface to Create2Metamorphic (11)
interface IMetamorphicFactory {
    function checkTrusted(address addr) external view returns (bool);
    function deployedContracts(bytes32 salt) external view returns (address);
}

contract AuthorityChain {
    address public owner;
    address public pendingOwner;
    uint256 public ownerTransferTime;
    
    uint256 public constant TRANSFER_DELAY = 2 days;
    uint256 public constant GUARDIAN_TTL = 6 hours;
    
    mapping(address => bool) public admins;
    mapping(address => bool) public delegates;
    mapping(address => address) public delegateApprovedBy;
    mapping(address => uint256) public delegateAddedAt;
    
    // Historical permissions - BUG: never cleared
    mapping(address => mapping(bytes4 => bool)) public historicalPermissions;
    
    // 🔗 CHAIN: Trust factory-deployed contracts
    IMetamorphicFactory public trustedFactory;
    
    struct GuardianRecord {
        uint64 clearanceLevel;
        uint64 mintedAt;
        bytes32 attestationHint;
    }

    mapping(address => GuardianRecord) public guardianBadge;

    uint256 public treasuryBalance;
    
    event OwnerTransferInitiated(address indexed newOwner, uint256 effectiveTime);
    event AdminAdded(address indexed admin);
    event DelegateAdded(address indexed delegate, address indexed approvedBy);
    event GuardianAttested(address indexed delegate, uint64 clearance, bytes32 hint);
    event Withdrawal(address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    /**
     * @dev BUG #1: Any admin can add delegates, delegates can act as admins
     * This creates emergent privilege: delegate → admin powers
     */
    modifier onlyAdmin() {
        require(admins[msg.sender] || msg.sender == owner, "Not admin");
        _;
    }
    
    /**
     * @dev BUG #2: Delegate check includes historical permissions
     * Revoked delegates retain access through historicalPermissions mapping
     */
    modifier onlyDelegate() {
        require(
            delegates[msg.sender] || 
            admins[msg.sender] || 
            msg.sender == owner ||
            historicalPermissions[msg.sender][msg.sig], // BUG: Never cleared
            "Not delegate"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    /**
     * @dev BUG #3: Pending owner can be frontrun
     * Between initiate and complete, anyone can race to drain
     */
    function initiateOwnerTransfer(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        ownerTransferTime = block.timestamp + TRANSFER_DELAY;
        emit OwnerTransferInitiated(newOwner, ownerTransferTime);
    }

    /**
     * @dev BUG #4: No check if current owner still wants transfer
     * Pending owner can complete even if owner changed mind
     */
    function completeOwnerTransfer() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        require(block.timestamp >= ownerTransferTime, "Too early");
        
        // BUG: Old owner's admin status persists
        owner = pendingOwner;
        admins[pendingOwner] = true;
        pendingOwner = address(0);
    }

    /**
     * @dev Admin can add other admins - seems normal but...
     * BUG #5: No limit on admin chain length
     */
    function addAdmin(address admin) external onlyAdmin {
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    /**
     * @dev BUG #6: Delegates approved by ANY admin, even later-revoked ones
     * And delegates can add OTHER delegates (transitive trust)
     */
    function addDelegate(address delegate) external onlyDelegate {
        delegates[delegate] = true;
        delegateApprovedBy[delegate] = msg.sender;
        delegateAddedAt[delegate] = block.timestamp;
        
        // BUG: Store historical permission - NEVER deleted
        historicalPermissions[delegate][this.withdraw.selector] = true;

        // New guardian badge - looks like a safety layer but delegates control it
        uint64 clearance = uint64(uint256(keccak256(abi.encodePacked(delegate, msg.sender, block.timestamp))) % 200 + 1);
        bytes32 hint = keccak256(abi.encodePacked(delegate, msg.sender, clearance));
        guardianBadge[delegate] = GuardianRecord({
            clearanceLevel: clearance,
            mintedAt: uint64(block.timestamp),
            attestationHint: hint
        });
        emit GuardianAttested(delegate, clearance, hint);
        
        emit DelegateAdded(delegate, msg.sender);
    }

    /**
     * @dev Revoke delegate - but historical permissions remain!
     */
    function revokeDelegate(address delegate) external onlyAdmin {
        delegates[delegate] = false;
        // BUG: historicalPermissions NOT cleared
        // Delegate can still call withdraw() via historical access

        // Looks like we downgrade guardian badge, but historical path still bypasses
        GuardianRecord storage badge = guardianBadge[delegate];
        if (badge.attestationHint != bytes32(0)) {
            badge.mintedAt = uint64(block.timestamp - (GUARDIAN_TTL * 2));
        }
    }
    
    // 🔗 CHAIN: Set trusted factory for metamorphic contracts
    function setTrustedFactory(address factory) external onlyOwner {
        trustedFactory = IMetamorphicFactory(factory);
    }
    
    // 🔗 CHAIN: Trust addresses deployed by factory
    // BUG: Trust persists even after selfdestruct + redeploy!
    function addFactoryDelegate(bytes32 salt) external onlyAdmin {
        require(address(trustedFactory) != address(0), "No factory");
        address deployed = trustedFactory.deployedContracts(salt);
        require(deployed != address(0), "Not deployed");
        
        // BUG: We trust the ADDRESS, not the bytecode
        // If contract is destroyed and redeployed, trust remains!
        delegates[deployed] = true;
        delegateApprovedBy[deployed] = msg.sender;
        delegateAddedAt[deployed] = block.timestamp;
        
        // Record historical permission
        historicalPermissions[deployed][this.withdraw.selector] = true;
        
        emit DelegateAdded(deployed, msg.sender);
    }

    /**
     * @dev Treasury withdraw - accessible by delegates
     * BUG #7: Revoked delegate can still access via historical permissions
     * 🔗 CHAIN BUG: Metamorphic redeployed contract inherits permissions!
     */
    function withdraw(uint256 amount) external onlyDelegate {
        require(_hasActiveGuardian(msg.sender), "guardian gate");
        require(amount <= treasuryBalance, "Insufficient balance");
        treasuryBalance -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Deposit to treasury
     */
    function deposit() external payable {
        treasuryBalance += msg.value;
    }

    /**
     * @dev BUG #8: Check function looks safe but ignores historical
     */
    function canWithdraw(address user) external view returns (bool) {
        if (delegates[user] || admins[user] || user == owner) {
            return true;
        }
        if (historicalPermissions[user][this.withdraw.selector]) {
            return true;
        }
        return _hasActiveGuardian(user);
    }

    receive() external payable {
        treasuryBalance += msg.value;
    }

    function submitGuardianAttestation(bytes32 hint) external onlyDelegate {
        uint64 clearance = uint64(uint256(keccak256(abi.encodePacked(msg.sender, hint, block.timestamp))) % 250) + 1;
        bytes32 attHint = keccak256(abi.encodePacked(msg.sender, delegateApprovedBy[msg.sender], clearance));
        guardianBadge[msg.sender] = GuardianRecord({
            clearanceLevel: clearance,
            mintedAt: uint64(block.timestamp),
            attestationHint: attHint
        });
        emit GuardianAttested(msg.sender, clearance, attHint);
    }

    function overrideGuardian(address account, bytes32 newHint, uint64 newClearance, bool freeze) external onlyOwner {
        GuardianRecord storage badge = guardianBadge[account];
        badge.attestationHint = newHint;
        badge.clearanceLevel = newClearance;
        if (freeze) {
            badge.mintedAt = 0;
        } else {
            badge.mintedAt = uint64(block.timestamp);
        }
        emit GuardianAttested(account, newClearance, newHint);
    }

    function _hasActiveGuardian(address user) internal view returns (bool) {
        GuardianRecord memory badge = guardianBadge[user];
        if (badge.clearanceLevel != 0 && badge.mintedAt != 0) {
            if (block.timestamp <= uint256(badge.mintedAt) + GUARDIAN_TTL) {
                return true; // Fresh attestation
            }
        }

        if (badge.attestationHint != bytes32(0)) {
            bytes32 recomputed = keccak256(abi.encodePacked(user, delegateApprovedBy[user], badge.clearanceLevel));
            if (recomputed == badge.attestationHint) {
                return true;
            }
        }

        if (historicalPermissions[user][this.withdraw.selector] && delegateAddedAt[user] != 0) {
            if (block.timestamp - delegateAddedAt[user] > 90 days) {
                return true;
            }
        }

        return false;
    }
}
