// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ProxyUpgradeAdvanced
 * @dev Training Contract #31 - Proxy / Upgrade / Diamond Advanced Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Beacon Upgrade Bypass (PROXY-ADV-01) — beacon upgraded without auth
 * 2. Proxy Fallback Misuse (PROXY-ADV-02) — fallback delegates everything blindly
 * 3. Implementation Rollback (PROXY-ADV-03) — no versioning allows rollback to buggy impl
 * 4. Upgrade Guardian Bypass (PROXY-ADV-04) — guardian bypassed via direct call
 * 5. Diamond Multi-Facet Misalignment (PROXY-ADV-05) — different storage layouts corrupt state
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): PROXY-ADV-01→05
 * - Engine 22 (storage-layout): storage collision in proxy pattern
 * - Engine 21 (bleeding-edge-detector): advanced proxy patterns
 *
 * REAL-WORLD EXAMPLES:
 * - Wormhole (~$320M, Feb 2022) — unguarded upgrade
 * - Nomad Bridge ($190M, Aug 2022) — implementation initialization
 */

// ========== VULN 1: Beacon Upgrade Bypass (PROXY-ADV-01) ==========

contract VulnerableBeacon {
    address public implementation;
    address public owner;

    event Upgraded(address indexed implementation);

    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }

    // BUG #1: no auth check on upgrade — anyone can change implementation for ALL proxies
    function upgradeTo(address newImplementation) external {
        // VULN: missing onlyOwner / access control
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    function getImplementation() external view returns (address) {
        return implementation;
    }
}

contract BeaconProxy {
    VulnerableBeacon public beacon;

    constructor(address _beacon) {
        beacon = VulnerableBeacon(_beacon);
    }

    fallback() external payable {
        address impl = beacon.getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// ========== VULN 2: Proxy Fallback Misuse (PROXY-ADV-02) ==========

contract BlindDelegateProxy {
    address public implementation;
    address public admin;
    uint256 public importantState;

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    // BUG #2: fallback delegates ALL calls including admin functions
    // Attacker can call setAdmin via implementation's matching selector
    fallback() external payable {
        address _impl = implementation;
        // VULN: no selector filtering — delegates even admin slot writes
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// ========== VULN 3: Implementation Rollback (PROXY-ADV-03) ==========

contract RollbackableProxy {
    address public implementation;
    address public admin;
    // BUG #3: no version tracking — admin can rollback to old buggy implementation
    address[] public implementationHistory;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
        implementationHistory.push(_impl);
    }

    function upgrade(address newImpl) external onlyAdmin {
        implementationHistory.push(newImpl);
        implementation = newImpl;
    }

    // VULN: can rollback to ANY previous implementation, including ones with known bugs
    function rollback(uint256 index) external onlyAdmin {
        require(index < implementationHistory.length, "invalid index");
        implementation = implementationHistory[index];
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// ========== VULN 4: Upgrade Guardian Bypass (PROXY-ADV-04) ==========

contract GuardedProxy {
    address public implementation;
    address public admin;
    address public guardian;
    uint256 public upgradeDelay = 2 days;
    uint256 public pendingUpgradeTime;
    address public pendingImplementation;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor(address _impl, address _guardian) {
        implementation = _impl;
        admin = msg.sender;
        guardian = _guardian;
    }

    function proposeUpgrade(address newImpl) external onlyAdmin {
        pendingImplementation = newImpl;
        pendingUpgradeTime = block.timestamp + upgradeDelay;
    }

    function executeUpgrade() external onlyAdmin {
        require(block.timestamp >= pendingUpgradeTime, "too early");
        require(pendingImplementation != address(0), "no pending");
        implementation = pendingImplementation;
        pendingImplementation = address(0);
    }

    // BUG #4: guardian can be bypassed by directly manipulating storage
    // via delegatecall in fallback — implementation can write to guardian slot
    function setGuardian(address newGuardian) external {
        require(msg.sender == guardian, "not guardian");
        guardian = newGuardian;
    }

    // VULN: implementation can overwrite guardian slot via delegatecall
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// ========== VULN 5: Diamond Multi-Facet Misalignment (PROXY-ADV-05) ==========

contract VulnerableDiamond {
    // Diamond storage
    struct DiamondStorage {
        mapping(bytes4 => address) facets;
        address owner;
    }

    // BUG #5: facets use different storage layouts
    // FacetA: slot 0 = balances mapping
    // FacetB: slot 0 = totalSupply
    // Writing to FacetA slot 0 corrupts FacetB's totalSupply

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        // VULN: storage position not using EIP-2535 standard slot
        // Uses slot 0 which conflicts with facet storage
        assembly {
            ds.slot := 0
        }
    }

    function addFacet(bytes4 selector, address facetAddress) external {
        DiamondStorage storage ds = diamondStorage();
        require(msg.sender == ds.owner, "not owner");
        ds.facets[selector] = facetAddress;
    }

    fallback() external payable {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.facets[msg.sig];
        require(facet != address(0), "no facet");

        // VULN: delegatecall to facet shares storage — different facets
        // may have incompatible storage layouts
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
