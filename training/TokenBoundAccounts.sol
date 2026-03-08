// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TokenBoundAccounts
 * @dev Training Contract #25 - ERC-6551 Token Bound Account Exploits
 *
 * Simulates a full ERC-6551 ecosystem with registry, account implementation,
 * nested ownership, and DeFi integrations — all riddled with 2026-era TBA vulnerabilities.
 *
 * VULNERABILITY CATEGORIES:
 * 1.  Recursive Ownership Loop — NFT A owns TBA-B which owns NFT-C which owns TBA-A
 * 2.  Trapped Assets — assets stuck in TBA when parent NFT burned or transferred
 * 3.  Transfer Reentrancy — TBA callback on NFT transfer allows re-entry
 * 4.  Registry Front-run — attacker creates TBA for victim's NFT before victim
 * 5.  Cross-chain TBA Desync — TBA on L1 vs L2 have inconsistent state
 * 6.  Ownership Confusion — TBA.owner() returns NFT owner but not during transfer
 * 7.  Execution Delegation Bypass — TBA executes calls on behalf of owner, no validation
 * 8.  Nested TBA Gas Bomb — deeply nested TBAs cause out-of-gas on ownership check
 * 9.  NFT Approval Drain — approving TBA for one action allows full account drain
 * 10. TBA Storage Collision — multiple TBA implementations for same NFT = storage clash
 *
 * REAL-WORLD CONTEXT:
 * - ERC-6551 (Token Bound Accounts) standard — Jayden Windle, Benny Giang
 * - Tokenbound SDK, Sapienz TBAs, Lens Protocol v2 account abstraction
 * - CryptoKitties → nested NFT ownership use cases
 * - Future Soul-bound TBA identity wallets (ERC-5192 + ERC-6551)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1: Pattern DB (TBA-01..05 patterns)
 * - Engine 5: Bleeding Edge (Frontier2026 — TokenBoundRecursion, TokenBoundReentrancy)
 * - Engine 10: Exploit Synth (TokenBoundTrap attack synthesis)
 * - Engine 8: Composability Checker (TokenBoundAccount external class)
 * - Engine 12: Fuzzing (TokenBoundTrap combo type)
 * - Engine 3: Reentrancy Detector (transfer callbacks)
 *
 * CROSS-CONTRACT CHAINS:
 * - Links to 06_CallbackReentrancy (reentrancy via callbacks)
 * - Links to 08_ProxyStorageCollision (storage collision patterns)
 * - Links to 18_AccountAbstractionVuln (AA wallet patterns, ERC-4337)
 * - Links to 11_Create2Metamorphic (deterministic address pre-computation)
 */

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

// ========== INTERFACES ==========

interface IERC6551Registry {
    function createAccount(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt,
        bytes calldata initData
    ) external returns (address);

    function account(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt
    ) external view returns (address);
}

interface IERC6551Account {
    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId);
    function owner() external view returns (address);
    function executeCall(address to, uint256 value, bytes calldata data) external payable returns (bytes memory);
}

// 🔗 CHAIN: Links to 06_CallbackReentrancy — callback-based reentrancy
// 🔗 CHAIN: Links to 18_AccountAbstractionVuln — account abstraction patterns

// ========== ERC-6551 REGISTRY (VULNERABLE) ==========

contract VulnerableERC6551Registry is IERC6551Registry {
    mapping(address => bool) public accountCreated;

    // VULN #4: No access control — anyone can create TBA for any NFT
    function createAccount(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt,
        bytes calldata initData
    ) external override returns (address) {
        // BUG: Deterministic address means attacker can front-run creation
        bytes32 saltHash = keccak256(abi.encodePacked(chainId, tokenContract, tokenId, salt));

        // VULN #4: No check that msg.sender owns the NFT
        // Attacker creates TBA with malicious implementation before NFT owner
        address accountAddr = Create2.deploy(
            0,
            saltHash,
            abi.encodePacked(
                type(TokenBoundAccount).creationCode,
                abi.encode(implementation, chainId, tokenContract, tokenId)
            )
        );

        // VULN #10: No registry of which implementation was used
        // Multiple calls with different implementations = storage collision
        accountCreated[accountAddr] = true;

        if (initData.length > 0) {
            // BUG: Arbitrary initialization — attacker can set malicious state
            (bool ok, ) = accountAddr.call(initData);
            require(ok, "Init failed");
        }

        return accountAddr;
    }

    function account(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt
    ) external view override returns (address) {
        bytes32 saltHash = keccak256(abi.encodePacked(chainId, tokenContract, tokenId, salt));
        return Create2.computeAddress(
            saltHash,
            keccak256(abi.encodePacked(
                type(TokenBoundAccount).creationCode,
                abi.encode(implementation, chainId, tokenContract, tokenId)
            ))
        );
    }
}

// ========== TOKEN BOUND ACCOUNT (VULNERABLE) ==========

contract TokenBoundAccount is IERC6551Account, IERC721Receiver {
    uint256 private _chainId;
    address private _tokenContract;
    uint256 private _tokenId;
    address private _implementation;

    uint256 private _nonce;
    bool private _initialized;

    // Delegations
    mapping(address => bool) public delegates;

    event Executed(address indexed target, uint256 value, bytes data);
    event DelegateAdded(address indexed delegate);

    constructor(address impl, uint256 chainId_, address tokenContract_, uint256 tokenId_) {
        _implementation = impl;
        _chainId = chainId_;
        _tokenContract = tokenContract_;
        _tokenId = tokenId_;
        _initialized = true;
    }

    // ========== OWNERSHIP (VULNERABLE) ==========

    function token() external view override returns (uint256, address, uint256) {
        return (_chainId, _tokenContract, _tokenId);
    }

    /// @notice Get the owner of this TBA (= owner of the parent NFT)
    // VULN #1: Doesn't detect recursive ownership loops
    // VULN #6: Returns wrong owner during NFT transfer hooks
    // VULN #8: Deep nesting causes gas bomb
    function owner() public view override returns (address) {
        address nftOwner = IERC721(_tokenContract).ownerOf(_tokenId);

        // VULN #1: If nftOwner is another TBA, recurse — can loop forever
        // BUG: No recursion depth limit
        // BUG: No cycle detection in ownership chain
        try IERC6551Account(nftOwner).owner() returns (address ultimate) {
            return ultimate; // VULN #8: Each recursion level costs gas
        } catch {
            return nftOwner;
        }
    }

    // ========== EXECUTION (VULNERABLE) ==========

    /// @notice Execute a call from this TBA
    // VULN #7: Minimal validation on what can be executed
    // VULN #9: Once approved, can execute anything
    function executeCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external payable override returns (bytes memory) {
        // VULN #6: owner() may return stale/wrong value during transfer
        require(msg.sender == owner() || delegates[msg.sender], "Not authorized");

        // VULN #7: No target validation — can call any contract
        // VULN #9: Delegates have FULL execution rights, no scoping
        // BUG: No reentrancy guard on execution
        _nonce++;

        (bool ok, bytes memory result) = to.call{value: value}(data);
        require(ok, "Execution failed");

        emit Executed(to, value, data);
        return result;
    }

    /// @notice Execute batch calls (even more dangerous)
    // VULN #7: Batch execution with no per-call validation
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable {
        require(msg.sender == owner() || delegates[msg.sender], "Not authorized");

        for (uint256 i = 0; i < targets.length; i++) {
            // BUG: No individual call validation or gas limit
            (bool ok, ) = targets[i].call{value: values[i]}(datas[i]);
            require(ok, "Batch call failed");
        }
    }

    // ========== DELEGATION (VULNERABLE) ==========

    /// @notice Add a delegate who can execute calls
    // VULN #9: Delegate gets unlimited execution power
    function addDelegate(address delegate) external {
        require(msg.sender == owner(), "Not owner");
        // BUG: No expiry on delegation
        // BUG: No scoping — delegate can do ANYTHING the TBA can
        delegates[delegate] = true;
        emit DelegateAdded(delegate);
    }

    /// @notice Remove a delegate
    function removeDelegate(address delegate) external {
        require(msg.sender == owner(), "Not owner");
        delegates[delegate] = false;
    }

    // ========== ASSET MANAGEMENT (VULNERABLE) ==========

    /// @notice Withdraw ERC20 tokens from this TBA
    // VULN #2: If NFT is burned, assets are trapped forever
    function withdrawERC20(address token_, uint256 amount) external {
        require(msg.sender == owner(), "Not owner");
        // VULN #2: owner() reverts if NFT is burned → funds trapped
        // BUG: No emergency withdrawal mechanism
        IERC20(token_).transfer(msg.sender, amount);
    }

    /// @notice Withdraw ETH from this TBA
    // VULN #2: Same trapped-asset problem for ETH
    function withdrawETH(uint256 amount) external {
        require(msg.sender == owner(), "Not owner");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    /// @notice Withdraw NFTs from this TBA
    // VULN #3: onERC721Received callback during transfer = reentrancy
    function withdrawNFT(address nftContract, uint256 tokenId_) external {
        require(msg.sender == owner(), "Not owner");
        // VULN #3: This transfer triggers onERC721Received on recipient
        // If recipient is another TBA, can re-enter and drain
        IERC721(nftContract).safeTransferFrom(address(this), msg.sender, tokenId_);
    }

    // ========== ERC721 RECEIVER (VULNERABLE) ==========

    // VULN #3: Callback on NFT receive allows re-entry
    function onERC721Received(
        address /* operator */,
        address /* from */,
        uint256 /* tokenId */,
        bytes calldata /* data */
    ) external override returns (bytes4) {
        // BUG: No reentrancy check — this is called during safeTransferFrom
        // Attacker can use this callback to call executeCall() re-entrantly
        return this.onERC721Received.selector;
    }

    // ========== CROSS-CHAIN (VULNERABLE) ==========

    /// @notice Sync TBA state to another chain
    // VULN #5: No verification that L2 TBA state matches L1
    function syncToL2(
        address bridge,
        uint256 targetChainId,
        bytes calldata syncData
    ) external {
        require(msg.sender == owner(), "Not owner");

        // VULN #5: Sends arbitrary syncData — no state root verification
        // BUG: L2 TBA could have completely different assets/state
        // BUG: No nonce to prevent replay attacks
        (bool ok, ) = bridge.call(
            abi.encodeWithSignature(
                "sendMessage(uint256,address,bytes)",
                targetChainId,
                address(this),
                syncData
            )
        );
        require(ok, "Sync failed");
    }

    receive() external payable {}
}

// ========== VULNERABLE NFT WITH TBA HOOKS ==========

contract TBAHostNFT is ERC721 {
    uint256 public nextTokenId;
    IERC6551Registry public registry;
    address public tbaImplementation;

    mapping(uint256 => address) public tokenTBA;

    constructor(address _registry, address _impl) ERC721("TBA Host", "TBAH") {
        registry = IERC6551Registry(_registry);
        tbaImplementation = _impl;
    }

    /// @notice Mint NFT and auto-create TBA
    // VULN #4: Auto-creation can be front-run
    function mintWithTBA() external returns (uint256 tokenId, address tba) {
        tokenId = nextTokenId++;
        _mint(msg.sender, tokenId);

        // VULN #4: Deterministic TBA address — attacker can predict and front-run
        tba = registry.createAccount(
            tbaImplementation,
            block.chainid,
            address(this),
            tokenId,
            0, // salt = 0, always
            "" // no init data
        );
        tokenTBA[tokenId] = tba;
    }

    /// @notice Transfer override — doesn't update TBA ownership cache
    // VULN #6: TBA.owner() returns new owner but cached auth may be stale
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        address from = super._update(to, tokenId, auth);
        // BUG: No notification to TBA about ownership change
        // Delegates of previous owner still have access until manually removed
        // VULN #6: Any in-flight TBA transactions still execute under old owner
        return from;
    }

    /// @notice Burn NFT — traps TBA assets
    // VULN #2: Burning parent NFT locks all TBA assets
    function burn(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "Not owner");
        _burn(tokenId);
        // VULN #2: tokenTBA[tokenId] still exists and holds assets
        // But owner() will revert because NFT no longer exists
        // All ETH, ERC20, and NFTs inside TBA are permanently trapped
    }
}

// ========== RECURSIVE OWNERSHIP ATTACK CONTRACT ==========

/// @notice Demonstrates VULN #1: Recursive ownership loop
contract RecursiveOwnershipAttack {
    TBAHostNFT public hostNFT;
    IERC6551Registry public registry;

    constructor(address _host, address _registry) {
        hostNFT = TBAHostNFT(_host);
        registry = IERC6551Registry(_registry);
    }

    /// @notice Create circular ownership: NFT-A → TBA-A → NFT-B → TBA-B → owns NFT-A
    // VULN #1: Causes infinite loop in owner() resolution
    function createLoop() external {
        // Step 1: Mint NFT-A, get TBA-A
        (uint256 tokenIdA, address tbaA) = hostNFT.mintWithTBA();

        // Step 2: Mint NFT-B, get TBA-B
        (uint256 tokenIdB, address tbaB) = hostNFT.mintWithTBA();

        // Step 3: Transfer NFT-B to TBA-A (TBA-A now owns NFT-B)
        hostNFT.transferFrom(msg.sender, tbaA, tokenIdB);

        // Step 4: Transfer NFT-A to TBA-B (TBA-B now owns NFT-A)
        // This creates: NFT-A → TBA-A → NFT-B → TBA-B → NFT-A ... infinite loop
        hostNFT.transferFrom(msg.sender, tbaB, tokenIdA);

        // Now calling owner() on either TBA will loop forever (gas bomb)
        // VULN #8: Each recursion burns gas until out-of-gas
    }
}
