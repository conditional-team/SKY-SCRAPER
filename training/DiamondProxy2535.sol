// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DiamondProxy2535
 * @dev Training Contract #52 - ERC-2535 Diamond Proxy Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Facet Selector Collision (DIAMOND-COLLISION-01)
 * 2. Storage Namespace Overlap (DIAMOND-STORAGE-01)
 * 3. Loupe Function Spoofing (DIAMOND-LOUPE-01)
 * 4. Uninitialized Facet (DIAMOND-UNINIT-01)
 * 5. DiamondCut Access Bypass (DIAMOND-CUT-01)
 * 6. Delegatecall to Malicious Facet (DIAMOND-DELEG-01)
 * 7. Facet Removal Leaves Storage (DIAMOND-REMNANT-01)
 * 8. Immutable Function Override (DIAMOND-IMMUT-01)
 * 9. Fallback Hijack (DIAMOND-FALLBACK-01)
 * 10. Init Function Replay (DIAMOND-INITREPLAY-01)
 * 11. Cross-Facet Reentrancy (DIAMOND-XREENTR-01)
 * 12. Storage Slot Frontrun (DIAMOND-SLOTFRONT-01)
 * 13. Facet Upgrade Timelock Bypass (DIAMOND-TIMELOCK-01)
 * 14. Diamond Beacon Confusion (DIAMOND-BEACON-01)
 * 15. Multi-Init Ordering Attack (DIAMOND-MULTIINIT-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): DIAMOND-*, proxy, delegatecall, storage collision
 * - Engine 2 (deep-semantic): storage layout, selector dispatch
 * - Engine 6 (proxy-analyzer): upgrade patterns, storage slots
 * - Engine 5 (reentrancy-checker): cross-facet reentrancy
 */

interface IDiamondCut {
    enum FacetCutAction { Add, Replace, Remove }
    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }
    function diamondCut(FacetCut[] calldata cuts, address init, bytes calldata initData) external;
}

// ========== Diamond Storage Lib ==========

library LibDiamond {
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 functionSelectorPosition;
    }

    struct DiamondStorage {
        mapping(bytes4 => FacetAddressAndPosition) selectorToFacet;
        mapping(address => uint256) facetCount;
        bytes4[] selectors;
        address contractOwner;
        mapping(bytes4 => bool) immutableFunctions;
        bool initialized;
        uint256 timelockEnd;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly { ds.slot := position }
    }
}

// ========== VULN 1: Facet Selector Collision (DIAMOND-COLLISION-01) ==========

contract DiamondProxy {
    // BUG #1: selector collision—different functions mapping to same 4-byte signature
    // e.g., `transfer(address,uint256)` and `func_2093253501(bytes)` share selector
    
    fallback() external payable {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        address facet = ds.selectorToFacet[msg.sig].facetAddress;
        require(facet != address(0), "function not found");
        
        // VULN: if two facets have colliding selectors, last one wins
        // silently overrides critical function with malicious one
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

// ========== VULN 2: Storage Namespace Overlap (DIAMOND-STORAGE-01) ==========

contract FacetA {
    // BUG #2: FacetA and FacetB use overlapping storage slots
    // Diamond storage pattern should use unique namespaces
    
    struct FacetAStorage {
        uint256 balance;
        address token;
        mapping(address => uint256) userBalances;
    }

    // VULN: hard-coded slot that may collide with FacetB
    bytes32 constant STORAGE_SLOT = keccak256("facet.a.storage");

    function _getStorage() internal pure returns (FacetAStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function deposit(uint256 amount) external {
        FacetAStorage storage s = _getStorage();
        s.userBalances[msg.sender] += amount;
        s.balance += amount;
    }
}

contract FacetB {
    struct FacetBStorage {
        uint256 balance;     // Same layout as FacetA!
        address admin;       // Overlaps with FacetA.token
        mapping(address => uint256) rewards;
    }

    // VULN: intentional or accidental slot collision with FacetA
    bytes32 constant STORAGE_SLOT = keccak256("facet.a.storage"); // SAME SLOT!

    function _getStorage() internal pure returns (FacetBStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function setAdmin(address _admin) external {
        FacetBStorage storage s = _getStorage();
        // VULN: writes to slot that FacetA reads as "token" address
        // corrupts FacetA's token pointer
        s.admin = _admin;
    }
}

// ========== VULN 3: Loupe Function Spoofing (DIAMOND-LOUPE-01) ==========

contract DiamondLoupeFacet {
    // BUG #3: loupe returns false information about facets
    // external tools rely on loupe to display contract info
    
    function facetAddresses() external view returns (address[] memory) {
        // VULN: can return different addresses than what's actually used
        // auditors/users see "safe" facets, but real routing goes to malicious ones
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        address[] memory fakeAddresses = new address[](1);
        fakeAddresses[0] = address(0xdead); // fake safe address
        return fakeAddresses; // hides real malicious facet
    }

    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory) {
        // Returns empty for malicious facet, hiding its functions
        return new bytes4[](0);
    }
}

// ========== VULN 4: Uninitialized Facet (DIAMOND-UNINIT-01) ==========

contract UninitializedFacet {
    bool private _initialized;
    address private _admin;

    // BUG #4: facet added without calling initializer
    // anyone can call init() and become admin
    function initialize(address admin) external {
        // VULN: no check if called through diamond proxy
        // direct call to facet implementation initializes it
        require(!_initialized, "already init");
        _admin = admin;
        _initialized = true;
    }

    function adminWithdraw(address token, uint256 amount) external {
        require(msg.sender == _admin, "not admin");
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", _admin, amount));
        require(ok);
    }
}

// ========== VULN 5: DiamondCut Access Bypass (DIAMOND-CUT-01) ==========

contract DiamondCutFacet {
    // BUG #5: diamondCut checks owner, but owner can be changed by another facet
    // OR init function can change owner during cut
    function diamondCut(
        IDiamondCut.FacetCut[] calldata cuts,
        address init,
        bytes calldata initData
    ) external {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        require(msg.sender == ds.contractOwner, "not owner");
        
        for (uint256 i = 0; i < cuts.length; i++) {
            IDiamondCut.FacetCut calldata cut = cuts[i];
            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                ds.selectorToFacet[cut.functionSelectors[j]].facetAddress = cut.facetAddress;
            }
        }
        
        // VULN: init function runs AFTER cuts are applied
        // init can call newly added malicious facet
        if (init != address(0)) {
            (bool ok, ) = init.delegatecall(initData);
            require(ok, "init failed");
        }
    }
}

// ========== VULN 6: Delegatecall to Malicious Facet (DIAMOND-DELEG-01) ==========

contract MaliciousFacet {
    // BUG #6: facet performs delegatecall to user-supplied address
    function executeAction(address target, bytes calldata data) external {
        // VULN: diamond proxy delegatecalls this facet, which delegatecalls target
        // attacker controls target—can modify diamond's storage arbitrarily
        (bool ok, ) = target.delegatecall(data);
        require(ok, "action failed");
    }
}

// ========== VULN 7: Facet Removal Leaves Storage (DIAMOND-REMNANT-01) ==========

contract StorageRemnantFacet {
    struct Config {
        address admin;
        uint256 fee;
        bool active;
    }

    bytes32 constant CONFIG_SLOT = keccak256("remnant.config");

    // BUG #7: when facet is removed, its storage values remain in diamond
    // new facet at same slot reads stale config
    function getConfig() internal pure returns (Config storage c) {
        bytes32 slot = CONFIG_SLOT;
        assembly { c.slot := slot }
    }

    function setConfig(address admin, uint256 fee) external {
        Config storage c = getConfig();
        c.admin = admin;
        c.fee = fee;
        c.active = true;
        // VULN: if this facet is removed and replaced, new facet inherits these values
        // old admin still has access through remnant storage
    }
}

// ========== VULN 8: Immutable Function Override (DIAMOND-IMMUT-01) ==========

contract OverrideFacet {
    // BUG #8: "immutable" functions in diamond can still be replaced
    // by replacing the facet address for that selector
    function markImmutable(bytes4 selector) external {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        require(msg.sender == ds.contractOwner);
        ds.immutableFunctions[selector] = true;
    }

    // VULN: diamondCut doesn't check immutableFunctions mapping
    // "immutable" is only advisory, not enforced
}

// ========== VULN 9: Fallback Hijack (DIAMOND-FALLBACK-01) ==========

contract FallbackHijackFacet {
    // BUG #9: register a wildcard fallback that catches unknown selectors
    // intercepts calls meant for legitimate facets not yet added
    
    // This facet registers selector 0x00000000 as catch-all
    // Any unknown function call routes here
    // VULN: intercepts governance, admin, and upgrade calls before they're properly routed
    
    function catchAll() external payable {
        // Silently succeeds, consuming user calls without executing intended logic
    }
}

// ========== VULN 10: Init Function Replay (DIAMOND-INITREPLAY-01) ==========

contract DiamondInit {
    // BUG #10: init function can be called multiple times if flag not in diamond storage
    bool private _localInitialized; // THIS IS FACET STORAGE, NOT DIAMOND STORAGE
    
    function init(address newOwner) external {
        // VULN: _localInitialized is in facet's own storage
        // when called via delegatecall, it writes to diamond's storage at slot 0
        // which may not be the intended flag location
        require(!_localInitialized);
        _localInitialized = true;
        
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        ds.contractOwner = newOwner;
    }
}

// ========== VULN 11: Cross-Facet Reentrancy (DIAMOND-XREENTR-01) ==========

contract VaultFacet {
    bytes32 constant VAULT_SLOT = keccak256("diamond.vault");
    
    struct VaultStorage {
        mapping(address => uint256) balances;
        uint256 totalDeposits;
        bool locked;
    }

    function _vault() internal pure returns (VaultStorage storage vs) {
        bytes32 slot = VAULT_SLOT;
        assembly { vs.slot := slot }
    }

    // BUG #11: no reentrancy guard shared across facets
    // FacetA.withdraw() calls external contract, which calls FacetB.withdraw()
    function withdraw(uint256 amount) external {
        VaultStorage storage vs = _vault();
        // VULN: reentrancy lock is per-facet, not shared in diamond storage
        require(vs.balances[msg.sender] >= amount, "insufficient");
        
        // External call before state update
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        
        vs.balances[msg.sender] -= amount;
        vs.totalDeposits -= amount;
    }

    function deposit() external payable {
        VaultStorage storage vs = _vault();
        vs.balances[msg.sender] += msg.value;
        vs.totalDeposits += msg.value;
    }
}

// ========== VULN 12: Storage Slot Frontrun (DIAMOND-SLOTFRONT-01) ==========

contract SlotFrontrunFacet {
    // BUG #12: attacker front-runs diamondCut to write to soon-to-be-used storage slot
    function writeSlot(bytes32 slot, uint256 value) external {
        // VULN: arbitrary storage write in diamond context
        assembly {
            sstore(slot, value)
        }
    }
}

// ========== VULN 13: Facet Upgrade Timelock Bypass (DIAMOND-TIMELOCK-01) ==========

contract TimelockCutFacet {
    uint256 public constant TIMELOCK_PERIOD = 2 days;

    // BUG #13: timelock on diamondCut, but owner can add "emergency" facet first
    // emergency facet bypasses timelock
    function scheduleCut(IDiamondCut.FacetCut[] calldata cuts) external {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        require(msg.sender == ds.contractOwner);
        // VULN: schedule stored but not enforced by separate execution
        ds.timelockEnd = block.timestamp + TIMELOCK_PERIOD;
    }

    function executeCut(IDiamondCut.FacetCut[] calldata cuts, address init, bytes calldata initData) external {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        require(msg.sender == ds.contractOwner);
        // VULN: timelock check uses >= instead of >, off-by-one
        // AND: scheduled cuts not compared to executed cuts
        require(block.timestamp >= ds.timelockEnd, "timelock");
        
        for (uint256 i = 0; i < cuts.length; i++) {
            for (uint256 j = 0; j < cuts[i].functionSelectors.length; j++) {
                ds.selectorToFacet[cuts[i].functionSelectors[j]].facetAddress = cuts[i].facetAddress;
            }
        }
    }
}

// ========== VULN 14: Diamond Beacon Confusion (DIAMOND-BEACON-01) ==========

contract DiamondBeacon {
    address public implementation;
    address public owner;

    constructor() { owner = msg.sender; }

    // BUG #14: using beacon pattern WITH diamond pattern
    // beacon upgrades override diamond facet routing
    function upgrade(address newImpl) external {
        require(msg.sender == owner);
        // VULN: beacon upgrade replaces ALL diamond routing
        // users think they're interacting with audited facets
        // but beacon points to completely different implementation
        implementation = newImpl;
    }
}

// ========== VULN 15: Multi-Init Ordering Attack (DIAMOND-MULTIINIT-01) ==========

contract MultiInit {
    // BUG #15: multiple init functions executed in order during diamondCut
    // later init can undo earlier init's security settings
    function multiInit(address[] calldata inits, bytes[] calldata datas) external {
        for (uint256 i = 0; i < inits.length; i++) {
            // VULN: no isolation between init calls
            // init[2] can overwrite security settings from init[0]
            (bool ok, ) = inits[i].delegatecall(datas[i]);
            require(ok, "init failed");
        }
    }
}
