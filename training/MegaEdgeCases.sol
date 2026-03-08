// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MegaEdgeCases
 * @dev Training Contract #45 - Mega Edge / Rare Case Patterns (30 vulns)
 *
 * VULNERABILITY CATEGORIES:
 * 1. EIP-3074 AUTH Abuse (MEGA-01)
 * 2. ERC4626 Share Price Manipulation (MEGA-02)
 * 3. Abi.encodePacked Collision (MEGA-03)
 * 4. Unprotected ETH Transfer (MEGA-04)
 * 5. Incorrect ERC20 Return Value (MEGA-05)
 * 6. Hardcoded Gas Stipend (MEGA-06)
 * 7. Token Decimals Mismatch (MEGA-07)
 * 8. Missing Zero Address Check (MEGA-08)
 * 9. Unprotected Proxy Admin Functions (MEGA-09)
 * 10. Constructor Not Payable (MEGA-10)
 * 11. Immutable After Deploy (MEGA-11)
 * 12. Fallback ETH Rejection (MEGA-12)
 * 13. Reentrancy via ERC777 Hooks (MEGA-13)
 * 14. Type Confusion in ABI Decode (MEGA-14)
 * 15. Modifier Order Dependency (MEGA-15)
 * 16. Integer Truncation (MEGA-16)
 * 17. Solidity Optimizer Bug (MEGA-17)
 * 18. Unbounded Dynamic Array (MEGA-18)
 * 19. Centralized Pause Mechanism (MEGA-19)
 * 20. Missing Slippage Protection (MEGA-20)
 * 21. Withdrawal Queue Manipulation (MEGA-21)
 * 22. Price Impact Not Checked (MEGA-22)
 * 23. Emergency Admin Backdoor (MEGA-23)
 * 24. Stale Price After Depeg (MEGA-24)
 * 25. Rebasing Token in DeFi (MEGA-25)
 * 26. Denial of Service via Revert (MEGA-26)
 * 27. Missing Deadline in Swap (MEGA-27)
 * 28. Private Data On-Chain (MEGA-28)
 * 29. Forced ETH via Selfdestruct (MEGA-29)
 * 30. Reentrancy Guard Bypass via View (MEGA-30)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): MEGA-01→30
 * - Engine 7 (deep-analyzer): logic, optimizer, modifier issues
 * - Engine 12 (precision-collapse-finder): decimal, truncation issues
 * - Engine 8 (negative-space-finder): missing checks and guards
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IERC777 {
    function send(address to, uint256 amount, bytes calldata data) external;
    function operatorSend(address from, address to, uint256 amount, bytes calldata data, bytes calldata operatorData) external;
}

interface IERC777Recipient {
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external;
}

interface IOracle {
    function getPrice(address) external view returns (uint256);
}

// ========== MEGA 01-10 ==========

contract MegaVault {
    // ========== State ==========
    address public owner;
    address public admin;
    address public implementation;
    address public oracle;
    uint256 public immutable deployFee; // BUG #11: MEGA-11
    bool public paused;

    mapping(address => uint256) public shares;
    mapping(address => uint256) public deposits;
    uint256 public totalShares;
    uint256 public totalAssets;
    IERC20 public asset;

    // BUG #28: MEGA-28 — private data on-chain
    uint256 private secret = 42; // VULN: readable via getStorageAt
    bytes32 private password = keccak256("admin123"); // VULN: plaintext derivable

    address[] public recipients;
    uint256[] public withdrawalQueue;
    mapping(uint256 => address) public queueOwner;
    mapping(uint256 => uint256) public queueAmount;
    uint256 public queueHead;
    uint256 public queueTail;
    uint256 public totalDeposits;
    uint256 public rewardRate;
    bool internal _locked;

    event Deposited(address indexed user, uint256 amount, uint256 shares);
    event Withdrawn(address indexed user, uint256 amount);

    // BUG #10: MEGA-10 — constructor not payable but references msg.value
    constructor(uint256 _fee) {
        owner = msg.sender;
        admin = msg.sender;
        deployFee = _fee;
        // VULN: expects ETH at deploy but constructor is NOT payable
        // Deploy with value will revert
    }

    // BUG #1: MEGA-01 — EIP-3074 AUTH abuse pattern
    // Simulated: authorized invoker pattern without proper invoker validation
    function authExecute(address invoker, address target, bytes calldata data) external {
        // VULN: no check that invoker is in whitelist
        // EIP-3074 AUTH/AUTHCALL — authorized invoker can execute anything
        require(msg.sender == invoker, "not invoker");
        (bool ok,) = target.call(data); // arbitrary delegation
        require(ok);
    }

    // BUG #2: MEGA-02 — ERC4626 share price manipulation
    function deposit(uint256 amount) external returns (uint256) {
        uint256 newShares;
        if (totalShares == 0) {
            newShares = amount; // first depositor: 1:1
        } else {
            // VULN: convertToShares rounds down
            // Attacker: deposit 1 wei → get 1 share → donate 1M tokens
            // Next depositor: 1M * 1 / (1M + 1) = 0 shares
            newShares = amount * totalShares / totalAssets;
        }
        require(newShares > 0, "zero shares");

        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += newShares;
        totalShares += newShares;
        totalAssets += amount;
        totalDeposits += amount;
        emit Deposited(msg.sender, amount, newShares);
        return newShares;
    }

    // BUG #3: MEGA-03 — abi.encodePacked collision
    function hashPacked(string calldata a, string calldata b) external pure returns (bytes32) {
        // VULN: abi.encodePacked("ab", "c") == abi.encodePacked("a", "bc")
        // Use abi.encode() instead for dynamic types
        return keccak256(abi.encodePacked(a, b));
    }

    // BUG #4: MEGA-04 — unprotected ETH transfer
    function sendETH(address payable to, uint256 amount) external {
        // VULN: no access control — anyone can drain contract ETH
        to.transfer(amount);
    }

    // BUG #5: MEGA-05 — incorrect ERC20 return value (USDT-like)
    function unsafeTransfer(address token, address to, uint256 amount) external {
        // VULN: USDT's transfer() doesn't return bool
        // This call will revert for non-standard tokens
        IERC20(token).transfer(to, amount);
        // Should use safeTransfer from SafeERC20
    }

    // BUG #6: MEGA-06 — hardcoded gas stipend
    function distributeReward(address payable winner, uint256 prize) external {
        // VULN: transfer() uses 2300 gas stipend
        // Fails if winner is a contract with complex fallback
        winner.transfer(prize);
        // Should use .call{value: amount}("") instead
    }

    // BUG #7: MEGA-07 — token decimals mismatch
    function calculateValue(address token, uint256 amount) external pure returns (uint256) {
        // VULN: assumes 18 decimals (1e18) but USDC has 6 decimals
        // Result is off by 1e12 for USDC
        uint256 priceInWei = 1e18; // hardcoded 18 decimals
        return amount * priceInWei / 1e18;
        // For USDC: 1000000 (1 USDC) * 1e18 / 1e18 = 1000000 (should be 1e18)
    }

    // BUG #8: MEGA-08 — missing zero address check
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        // VULN: newOwner can be address(0), locking the contract forever
        owner = newOwner;
    }

    // BUG #9: MEGA-09 — unprotected proxy admin functions
    function changeImplementation(address newImpl) external {
        // VULN: no access control — anyone can change implementation
        implementation = newImpl;
    }

    function changeAdmin(address newAdmin) external {
        // VULN: no access control — anyone can become admin
        admin = newAdmin;
    }

    // BUG #12: MEGA-12 — balance check assumes no force-fed ETH
    function checkInvariant() external view {
        // VULN: address(this).balance can be > totalDeposits
        // if ETH forced via selfdestruct
        require(address(this).balance == totalDeposits, "invariant broken");
    }

    // BUG #13: MEGA-13 — reentrancy via ERC777 hooks
    function depositERC777(IERC777 token, uint256 amount) external {
        // VULN: ERC777 send() calls tokensReceived hook — reentrancy
        deposits[msg.sender] += amount;
        token.send(address(this), amount, "");
        // tokensReceived hook fires during send, allowing re-entry
    }

    // BUG #14: MEGA-14 — type confusion in abi.decode
    function decodeMessage(bytes calldata data) external pure returns (address, uint256) {
        // VULN: if data was encoded as (uint256, address) but decoded as (address, uint256)
        // the values are interpreted wrong
        (address to, uint256 amount) = abi.decode(data, (address, uint256));
        return (to, amount);
    }

    // BUG #15: MEGA-15 — modifier order dependency
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "reentrancy");
        _locked = true;
        _;
        _locked = false;
    }

    // VULN: onlyOwner checked FIRST, then nonReentrant
    // If owner check fails, nonReentrant never sets _locked
    // Should be: nonReentrant onlyOwner (reentrancy guard first)
    function riskyWithdraw(uint256 amount) external onlyOwner nonReentrant {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }

    // BUG #16: MEGA-16 — integer truncation
    function truncateAmount(uint256 bigAmount) external pure returns (uint128) {
        // VULN: if bigAmount > type(uint128).max, value silently truncated
        return uint128(bigAmount);
        // Should use SafeCast.toUint128()
    }

    // BUG #18: MEGA-18 — unbounded dynamic array
    function addRecipient(address r) external {
        recipients.push(r);
        // VULN: array grows without limit
    }

    function processAll() external {
        // VULN: iterating unbounded array — will exceed block gas limit
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1);
        }
    }

    // BUG #19: MEGA-19 — centralized pause
    function pause() external onlyOwner {
        // VULN: single owner can pause indefinitely, no timelock
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    // BUG #20: MEGA-20 — missing slippage protection
    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256) {
        uint256 amountOut = amountIn * totalAssets / totalShares;
        // VULN: no minAmountOut parameter — 100% slippage allowed
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
        return amountOut;
    }

    // BUG #21: MEGA-21 — withdrawal queue manipulation
    function requestWithdrawal(uint256 amount) external {
        uint256 id = queueTail++;
        queueOwner[id] = msg.sender;
        queueAmount[id] = amount;
        withdrawalQueue.push(id);
    }

    function processQueue(uint256 count) external {
        // VULN: anyone can process queue, potentially skipping entries
        for (uint i = 0; i < count && queueHead < queueTail; i++) {
            uint256 id = queueHead++;
            address to = queueOwner[id];
            uint256 amount = queueAmount[id];
            // No check that caller is authorized to process
            payable(to).transfer(amount);
        }
    }

    // BUG #22: MEGA-22 — price impact not checked
    function tradeWithImpact(uint256 amount) external {
        uint256 reserve = totalAssets;
        uint256 output = amount * reserve / (reserve + amount);
        // VULN: no price impact check — single trade can move price 50%+
        totalAssets -= output;
    }

    // BUG #23: MEGA-23 — emergency admin backdoor
    function emergencyWithdraw() external onlyOwner {
        // VULN: no timelock, no multisig — admin drains everything instantly
        uint256 balance = address(this).balance;
        payable(owner).transfer(balance);
    }

    // BUG #24: MEGA-24 — stale price after depeg
    function getStablecoinValue(uint256 usdcAmount) external pure returns (uint256) {
        // VULN: hardcoded 1 USD for USDC — doesn't account for depeg events
        uint256 price = 1e18; // assume USDC always = 1 USD
        return usdcAmount * price / 1e6;
    }

    // BUG #25: MEGA-25 — rebasing token not handled
    function depositRebasing(IERC20 token, uint256 amount) external {
        deposits[msg.sender] += amount;
        token.transferFrom(msg.sender, address(this), amount);
        // VULN: if token rebases, actual balance changes without transfer
        // deposits[user] becomes incorrect — should track shares not amounts
    }

    // BUG #26: MEGA-26 — DoS via revert in loop
    function distributeToAll(uint256 perUser) external {
        // VULN: if ANY recipient reverts (contract without receive), entire loop fails
        // One malicious user blocks payments to everyone
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(perUser);
        }
    }

    // BUG #27: MEGA-27 — missing deadline in swap
    function swapWithoutDeadline(address tokenIn, uint256 amount) external {
        // VULN: using block.timestamp as deadline = no deadline at all
        // Tx can sit in mempool for hours/days and execute at stale price
        uint256 deadline = block.timestamp; // always passes
        require(block.timestamp <= deadline, "expired"); // useless check
        // Execute swap...
    }

    // BUG #29: MEGA-29 — forced ETH via selfdestruct
    function getBalance() external view returns (uint256) {
        // VULN: strict equality check — broken by selfdestruct force-feeding
        // address(this).balance can be > totalDeposits due to SELFDESTRUCT
        require(address(this).balance == totalDeposits, "mismatch");
        return totalDeposits;
    }

    // BUG #30: MEGA-30 — reentrancy guard bypass via view function
    function getSharePrice() external view returns (uint256) {
        // VULN: view function NOT protected by nonReentrant
        // During reentrancy, totalAssets/totalShares are in inconsistent state
        // External protocols reading this view get wrong price
        if (totalShares == 0) return 1e18;
        return totalAssets * 1e18 / totalShares;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        // VULN: same issue — view readable during reentrancy window
        if (totalShares == 0) return assets;
        return assets * totalShares / totalAssets;
    }

    receive() external payable {
        totalDeposits += msg.value;
    }
}

// BUG #17: MEGA-17 — solidity optimizer bug (affected versions)
// NOTE: This contract uses 0.8.19 which is safe, but the pattern shows
// code that WOULD be affected in vulnerable compiler versions (0.8.13-0.8.17)
contract OptimizerBugProne {
    // In Solidity 0.8.13-0.8.17, optimizer could incorrectly remove
    // necessary memory cleanup or abi.encode operations
    function encodeAndHash(uint256[] memory data) external pure returns (bytes32) {
        bytes memory encoded = abi.encode(data);
        // Optimizer might incorrectly optimize memory layout here
        assembly {
            // Memory operations that interact with optimizer
            let ptr := mload(0x40)
            mstore(ptr, mload(add(encoded, 0x20)))
        }
        return keccak256(encoded);
    }
}

// Helper: contract that force-sends ETH via selfdestruct
contract ForceFeeder {
    // BUG #29 helper: force ETH to any address
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}
