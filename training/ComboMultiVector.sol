// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ComboMultiVector
 * @dev Training Contract #44 - Cross-Combo Multi-Vector Patterns (17 vulns)
 *
 * VULNERABILITY CATEGORIES:
 * 1. Flash Loan + Governance Takeover (COMBO-01)
 * 2. Reentrancy + Oracle Manipulation (COMBO-02)
 * 3. Upgrade + Selfdestruct (COMBO-03)
 * 4. MEV + Flash Loan Arb (COMBO-04)
 * 5. Cross-Chain Flash Loan (COMBO-05)
 * 6. Proxy + Delegatecall Collision (COMBO-06)
 * 7. Oracle + AMM Feedback Loop (COMBO-07)
 * 8. Token Callback + Reentrancy (COMBO-08)
 * 9. Frontrun + Init (COMBO-09)
 * 10. Liquidation + Reentrancy (COMBO-10)
 * 11. Fee-on-Transfer + Rounding (COMBO-11)
 * 12. Bridge + Replay Attack (COMBO-12)
 * 13. Permit + Phishing (COMBO-13)
 * 14. Assembly + Proxy Storage (COMBO-14)
 * 15. Vault + Flash Loan Share Inflation (COMBO-15)
 * 16. CREATE2 + Metamorphic Contract (COMBO-16)
 * 17. Multi-Token Reentrancy (COMBO-17)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): COMBO-01→17
 * - Engine 7 (deep-analyzer): multi-vector analysis
 * - Engine 10 (cross-contract): cross-contract interactions
 */

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IFlashLender {
    function flashLoan(uint256 amount) external;
}

interface IOracle {
    function getPrice(address) external view returns (uint256);
    function update(address) external;
}

contract ComboExploits {
    // ========== Governance State ==========
    mapping(address => uint256) public votingPower;
    mapping(uint256 => bool) public proposalExecuted;
    uint256 public totalVotes;
    uint256 public quorum = 1000;

    // ========== Vault State ==========
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;
    IERC20 public asset;

    // ========== Oracle State ==========
    mapping(address => uint256) public prices;
    mapping(address => uint256) public lastUpdate;

    // ========== Bridge State ==========
    mapping(bytes32 => bool) public processedMessages;
    uint256 public chainId;
    address public relayer;

    // ========== Proxy State ==========
    address public implementation;
    address public admin;
    bool public initialized;

    // ========== Lending State ==========
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    event ProposalExecuted(uint256 id);
    event Deposit(address user, uint256 amount, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
        admin = msg.sender;
        chainId = block.chainid;
    }

    // BUG #1: COMBO-01 — flash loan → borrow governance tokens → vote → repay
    function flashVote(uint256 proposalId) external {
        // Step 1: Flash borrow huge amount of governance tokens
        uint256 borrowed = votingPower[msg.sender]; // from flash loan
        // VULN: snapshot at current block — flash loaned tokens count
        require(borrowed >= quorum, "not enough votes");
        proposalExecuted[proposalId] = true;
        // Step 2: Repay in same tx — never actually held tokens
        emit ProposalExecuted(proposalId);
    }

    // BUG #2: COMBO-02 — reentrancy during oracle-dependent swap
    function swapWithOracle(address token, uint256 amount) external {
        uint256 price = prices[token];
        uint256 outputAmount = amount * price / 1e18;

        // VULN: external call before state update + oracle-dependent pricing
        // Attacker: manipulate oracle → reenter during callback → get better price
        (bool ok,) = msg.sender.call{value: outputAmount}("");
        require(ok);

        // State updated AFTER external call
        totalAssets -= outputAmount;
    }

    // BUG #3: COMBO-03 — upgrade to contract that selfdestructs
    function upgradeTo(address newImpl) external {
        require(msg.sender == admin, "not admin");
        // VULN: new implementation can contain selfdestruct
        // Admin upgrades → calls selfdestruct → proxy becomes useless
        implementation = newImpl;
    }

    function delegateToImpl(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = implementation.delegatecall(data);
        require(ok);
        return result;
    }

    // BUG #4: COMBO-04 — MEV + flash loan sandwich
    function swapNoProtection(address tokenIn, uint256 amount) external {
        // VULN: no slippage protection + flash loan amplification
        // Attacker: flash loan → buy tokenIn → victim swaps at bad price → sell → repay
        uint256 outputAmount = amount * prices[tokenIn] / 1e18;
        totalAssets -= outputAmount;
    }

    // BUG #5: COMBO-05 — cross-chain flash loan (borrow on L1, use on L2)
    function crossChainFlash(uint256 amount, uint256 destChain) external {
        // VULN: flash loan on chain A, bridge to chain B, exploit, bridge back
        // Arbitrage between chains in single "transaction" window
        asset.transferFrom(msg.sender, address(this), amount);
        // Send bridge message to destChain...
    }

    // BUG #6: COMBO-06 — proxy delegatecall + function selector collision
    function proxyFallback(bytes calldata data) external {
        // VULN: if implementation has function with same selector as proxy admin functions,
        // user calls admin function through proxy, hits implementation instead
        bytes4 selector = bytes4(data[:4]);
        // No selector collision check
        (bool ok,) = implementation.delegatecall(data);
        require(ok);
    }

    // BUG #7: COMBO-07 — oracle reads AMM price, AMM trades move oracle
    function updateAndSwap(address token, uint256 amount) external {
        // Step 1: Large trade moves AMM price
        totalAssets -= amount;

        // Step 2: Oracle reads new (manipulated) AMM price
        // VULN: circular dependency — AMM price feeds oracle, oracle feeds lending
        prices[token] = totalAssets * 1e18 / totalShares; // spot price from pool
        // Step 3: Use inflated oracle price for lending
    }

    // BUG #8: COMBO-08 — ERC-777 token callback + reentrancy
    function depositToken(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        // VULN: if asset is ERC-777, transferFrom triggers tokensReceived hook
        // Attacker re-enters deposit with credits from callback
        uint256 newShares = amount * totalShares / totalAssets;
        shares[msg.sender] += newShares;
        totalShares += newShares;
        totalAssets += amount;
        emit Deposit(msg.sender, amount, newShares);
    }

    // BUG #9: COMBO-09 — front-run initialization + set malicious params
    function initializeVault(address _asset, uint256 _quorum) external {
        require(!initialized, "done");
        // VULN: attacker front-runs deploy tx, initializes with own params
        asset = IERC20(_asset);
        quorum = _quorum; // set quorum to 1 — single vote passes anything
        admin = msg.sender;
        initialized = true;
    }

    // BUG #10: COMBO-10 — liquidation callback allows reentrancy
    function liquidatePosition(address user) external {
        require(collateral[user] * prices[address(asset)] / debt[user] < 1.5e18, "healthy");

        uint256 seized = collateral[user];
        // VULN: external call during liquidation — liquidator re-enters
        (bool ok,) = msg.sender.call{value: seized}("");
        require(ok);

        // State updated AFTER external call
        collateral[user] = 0;
        debt[user] = 0;
    }

    // BUG #11: COMBO-11 — fee-on-transfer token + vault accounting
    function depositFeeToken(uint256 amount) external {
        uint256 balBefore = asset.balanceOf(address(this));
        asset.transferFrom(msg.sender, address(this), amount);
        uint256 balAfter = asset.balanceOf(address(this));
        // VULN: actual received = balAfter - balBefore < amount due to transfer fee
        // But shares are minted based on `amount` not actual received
        uint256 newShares = amount * totalShares / totalAssets; // should use (balAfter - balBefore)
        shares[msg.sender] += newShares;
        totalShares += newShares;
        totalAssets += amount; // accounting mismatch
    }

    // BUG #12: COMBO-12 — bridge message replay across chains
    function processMessage(bytes32 messageHash, uint256 sourceChain, bytes calldata data) external {
        // VULN: messageHash doesn't include destination chainId
        // Same message processable on multiple destination chains
        require(!processedMessages[messageHash], "processed");
        processedMessages[messageHash] = true;
        // Execute bridged action...
    }

    // BUG #13: COMBO-13 — EIP-2612 permit + phishing approval
    function permitAndTransfer(
        address owner_, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        // VULN: user signs permit thinking it's for dApp A
        // but attacker uses it for dApp B — permit is generic
        // Phishing site collects signatures for malicious permits
        // No domain-specific binding verification here
    }

    // BUG #14: COMBO-14 — assembly sstore in proxy context
    function writeSlot(uint256 slot, uint256 value) external {
        require(msg.sender == admin, "not admin");
        // VULN: in proxy context, this writes to PROXY storage
        // Can overwrite any slot including implementation address
        assembly {
            sstore(slot, value)
        }
    }

    // BUG #15: COMBO-15 — vault share inflation via flash loan + donation
    function deposit(uint256 amount) external returns (uint256) {
        uint256 newShares;
        if (totalShares == 0) {
            newShares = amount;
        } else {
            newShares = amount * totalShares / totalAssets;
        }
        // VULN: attacker deposits 1 wei → gets 1 share
        // Then donates 1M tokens directly (totalAssets increases)
        // Next depositor: 1M * 1 / 1M+1 = 0 shares → stolen
        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += newShares;
        totalShares += newShares;
        totalAssets += amount;
        return newShares;
    }

    // BUG #16: COMBO-16 — CREATE2 + metamorphic: deploy → selfdestruct → redeploy
    function deployMetamorphic(bytes memory initCode, bytes32 salt) external returns (address) {
        address deployed;
        assembly {
            deployed := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        // VULN: if deployed contract has selfdestruct, can be destroyed
        // then redeployed at same address with DIFFERENT code
        // Any approval/trust based on address is broken
        return deployed;
    }

    // BUG #17: COMBO-17 — multi-token reentrancy (ERC-721 + ERC-1155)
    function multiTokenSwap(
        address nft721, uint256 tokenId721,
        address nft1155, uint256 tokenId1155, uint256 amount1155
    ) external {
        // VULN: multiple token callbacks create complex reentrancy
        // onERC721Received → re-enter → onERC1155Received → re-enter again
        // State machine becomes inconsistent
        bytes4 received721 = IERC721Receiver(msg.sender).onERC721Received(
            address(this), msg.sender, tokenId721, ""
        );
        // After first callback, attacker has modified state
        bytes4 received1155 = IERC1155Receiver(msg.sender).onERC1155Received(
            address(this), msg.sender, tokenId1155, amount1155, ""
        );
    }

    receive() external payable {}
}

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}

interface IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
}
