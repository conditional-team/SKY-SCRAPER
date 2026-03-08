// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AdvancedReentrancy
 * @dev Training Contract #28 - Advanced Reentrancy Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Delegatecall Vault Reentrancy (RENT-ADV-01) — reentrancy via delegatecall on upgradeable vault
 * 2. Pull/Push Pattern Mixed Reentrancy (RENT-ADV-02) — mixing pull (withdraw) and push (send)
 * 3. Factory/Clone Reentrancy (RENT-ADV-03) — reentrancy during CREATE/CREATE2 before init
 * 4. NFT Lazy Mint Reentrancy (RENT-ADV-04) — re-mint via onERC721Received callback
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): RENT-ADV-01→04
 * - Engine 6 (CallbackReentrancy): callback-based reentrancy
 * - Engine 19 (deep-analyzer): cross-function reentrancy paths
 *
 * REAL-WORLD EXAMPLES:
 * - Rari Capital Fuse Pool ($80M, Apr 2022) — delegatecall reentrancy
 * - Cream Finance ($130M, Oct 2021) — cross-contract reentrancy
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external returns (bytes4);
}

// ========== VULN 1: Delegatecall Vault Reentrancy (RENT-ADV-01) ==========

contract DelegatecallVault {
    address public implementation;
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }

    // BUG #1: delegatecall to user-controlled implementation
    // Attacker can set implementation to malicious contract and re-enter
    function upgradeAndCall(address newImpl, bytes calldata data) external {
        // VULN: no auth check on upgrade
        implementation = newImpl;
        // VULN: delegatecall executes in OUR storage context
        (bool success,) = newImpl.delegatecall(data);
        require(success, "delegatecall failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // BUG: delegatecall shares storage — reentrancy guard in implementation
    // doesn't protect proxy storage
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // VULN: state updated AFTER delegatecall, attacker can re-enter
        (bool success,) = implementation.delegatecall(
            abi.encodeWithSignature("processWithdraw(address,uint256)", msg.sender, amount)
        );
        require(success);
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }
}

// ========== VULN 2: Pull/Push Pattern Mixed Reentrancy (RENT-ADV-02) ==========

contract PullPushMixed {
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public deposits;
    uint256 public totalPool;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalPool += msg.value;
    }

    // Push pattern: sends ETH directly
    function distributeRewards(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint i = 0; i < recipients.length; i++) {
            // BUG #2: push send during state changes allows recipient to re-enter
            // via receive/fallback and call withdrawPending()
            (bool ok,) = recipients[i].call{value: amounts[i]}("");
            require(ok, "send failed");
            totalPool -= amounts[i];
        }
    }

    // Pull pattern: user withdraws pending
    function withdrawPending() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "nothing pending");
        // BUG: cross-function reentrancy — distributeRewards calls external,
        // attacker re-enters here before totalPool is updated
        pendingWithdrawals[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function addPending(address user, uint256 amount) external {
        pendingWithdrawals[user] += amount;
    }
}

// ========== VULN 3: Factory/Clone Reentrancy (RENT-ADV-03) ==========

contract VulnerableFactory {
    mapping(address => bool) public isClone;
    mapping(address => uint256) public cloneBalances;
    uint256 public totalClones;
    address[] public allClones;

    event CloneCreated(address indexed clone, address indexed creator);

    // BUG #3: CREATE deploys and calls constructor, which can callback
    // into factory before isClone[addr] = true
    function createClone(bytes memory bytecode, bytes32 salt) external payable returns (address clone) {
        assembly {
            clone := create2(callvalue(), add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(clone != address(0), "create2 failed");
        // VULN: clone constructor already ran — if it called back into factory,
        // isClone was false at that point, bypassing checks
        allClones.push(clone);
        totalClones++;
        isClone[clone] = true;
        cloneBalances[clone] = msg.value;
        emit CloneCreated(clone, msg.sender);
    }

    // This function trusts isClone, but during CREATE2 the clone isn't registered yet
    function cloneAction(address clone) external {
        require(isClone[clone], "not a clone");
        // ... action that clone can exploit during creation
    }

    function onlyCloneDeposit() external payable {
        require(isClone[msg.sender], "only clones"); // bypassed during creation
        cloneBalances[msg.sender] += msg.value;
    }
}

// ========== VULN 4: NFT Lazy Mint Reentrancy (RENT-ADV-04) ==========

contract LazyMintNFT {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    uint256 public totalMinted;
    uint256 public maxSupply = 10000;
    uint256 public price = 0.1 ether;

    mapping(bytes32 => bool) public usedSignatures;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    // BUG #4: onERC721Received callback fires BEFORE state is fully updated
    // allowing re-mint of same tokenId or exceeding maxSupply
    function lazyMint(uint256 tokenId, bytes calldata signature) external payable {
        require(msg.value >= price, "underpaid");
        require(ownerOf[tokenId] == address(0), "already minted");
        require(totalMinted < maxSupply, "sold out");

        // VULN: signature marked used, but _safeMint callback fires before totalMinted++
        bytes32 sigHash = keccak256(signature);
        require(!usedSignatures[sigHash], "sig used");
        usedSignatures[sigHash] = true;

        // _safeMint equivalent with callback
        ownerOf[tokenId] = msg.sender;
        balanceOf[msg.sender]++;
        emit Transfer(address(0), msg.sender, tokenId);

        // VULN: callback BEFORE totalMinted is incremented
        // attacker can re-enter with different tokenId, bypassing maxSupply check
        if (_isContract(msg.sender)) {
            require(
                IERC721Receiver(msg.sender).onERC721Received(
                    msg.sender, address(0), tokenId, ""
                ) == IERC721Receiver.onERC721Received.selector,
                "unsafe recipient"
            );
        }

        totalMinted++; // too late — already called back
    }

    function _isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}
