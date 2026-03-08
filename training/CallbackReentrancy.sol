// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CallbackReentrancy
 * @dev Training Contract #6 - Hidden Atomicity + Reentrancy via Callback
 * 
 * SUBTLE VULNERABILITIES (Grey Area):
 * 1. Callback to user-controlled address before state update
 * 2. "Safe" ERC721 receive hook allows reentry
 * 3. Cross-function reentrancy (function A calls B, B is reentrant)
 * 4. Read-only reentrancy (view function called during state change)
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1: Pattern Scan (reentrancy patterns)
 * - Engine 15: Composability Analyzer
 * - Engine 29: Symbolic Execution
 * - Engine 2: Deep Semantic
 * 
 * COMBO: AssumptionArchetype::HiddenAtomicity
 * 
 * CHAIN INTEGRATION:
 * - Step 3 in MEDIUM chain: Callback during transient state allows extra mints
 * - TransientStorageLeak (13) sets state, callback reenters
 */

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// 🔗 CHAIN: Interface to TransientStorageLeak (13)
interface ITransientLeak {
    function isFlashLoanActive() external view returns (bool);
    function isLocked() external view returns (bool);
}

contract CallbackReentrancy {
    // === STATE ===
    mapping(uint256 => address) public tokenOwner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public pendingRewards;
    
    uint256 public totalSupply;
    uint256 public rewardPool;
    
    // BUG #1: No reentrancy guard
    // bool private _locked;
    
    // BUG #2: State variable read during callback
    uint256 public lastPrice;
    
    // 🔗 CHAIN: Transient storage for cross-contract state
    ITransientLeak public transientContract;
    
    event Minted(address indexed to, uint256 tokenId);
    event Burned(address indexed from, uint256 tokenId);
    event RewardsClaimed(address indexed user, uint256 amount);

    constructor() {
        rewardPool = 10 ether;
    }
    
    // 🔗 CHAIN: Set transient contract
    function setTransientContract(address _transient) external {
        transientContract = ITransientLeak(_transient);
    }

    /**
     * @dev Mint token with callback
     * BUG #3: Callback before state update = classic reentrancy
     * 🔗 CHAIN BUG: Free mint during flash loan active state!
     */
    function safeMint(address to, uint256 tokenId) external payable {
        // 🔗 CHAIN: Check if transient flash loan is active = free mint!
        bool freeMint = false;
        if (address(transientContract) != address(0)) {
            try transientContract.isFlashLoanActive() returns (bool active) {
                freeMint = active; // During flash loan = free NFTs!
            } catch {}
        }
        
        if (!freeMint) {
            require(msg.value >= 0.1 ether, "Insufficient payment");
        }
        require(tokenOwner[tokenId] == address(0), "Already minted");
        
        // Add to balances BEFORE callback - seems safe...
        balances[to]++;
        totalSupply++;
        
        // BUG: tokenOwner NOT set before callback!
        // Attacker can reenter and mint same tokenId again
        
        // Callback to receiver (user-controlled code)
        if (to.code.length > 0) {
            require(
                IERC721Receiver(to).onERC721Received(msg.sender, address(0), tokenId, "") ==
                IERC721Receiver.onERC721Received.selector,
                "Unsafe recipient"
            );
        }
        
        // State update AFTER callback - VULNERABLE
        tokenOwner[tokenId] = to;
        
        emit Minted(to, tokenId);
    }

    /**
     * @dev Burn token and claim rewards
     * BUG #4: Cross-function reentrancy via _claimRewards
     */
    function burnAndClaim(uint256 tokenId) external {
        require(tokenOwner[tokenId] == msg.sender, "Not owner");
        
        // Update state first - seems safe...
        tokenOwner[tokenId] = address(0);
        balances[msg.sender]--;
        totalSupply--;
        
        // BUG: Calculate rewards BEFORE burning actually completes
        // If _claimRewards reenters, rewards calculated on stale state
        uint256 rewards = _calculateRewards(msg.sender);
        pendingRewards[msg.sender] += rewards;
        
        // Internal claim - but this has external call!
        _claimRewards(msg.sender);
        
        emit Burned(msg.sender, tokenId);
    }

    /**
     * @dev Internal claim - hidden external call
     * BUG #5: Internal function has external call = unexpected reentrancy
     */
    function _claimRewards(address user) internal {
        uint256 amount = pendingRewards[user];
        if (amount == 0) return;
        
        // BUG: State change AFTER external call
        // pendingRewards[user] = 0; // Should be HERE
        
        (bool success, ) = user.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State change AFTER external call - VULNERABLE
        pendingRewards[user] = 0;
        
        emit RewardsClaimed(user, amount);
    }

    /**
     * @dev Calculate rewards based on balance
     * BUG #6: Read-only reentrancy - reads state during reentry
     */
    function _calculateRewards(address user) internal view returns (uint256) {
        if (totalSupply == 0) return 0;
        
        // BUG: During reentry, balances[user] might be inconsistent
        // totalSupply decremented but balances not yet
        return (rewardPool * balances[user]) / totalSupply;
    }

    /**
     * @dev Get price - called by other contracts
     * BUG #7: Read-only reentrancy - returns stale price during callback
     */
    function getPrice() external view returns (uint256) {
        // During callback, this returns STALE value
        // Other contracts might use this for pricing decisions
        return lastPrice;
    }

    /**
     * @dev Update price with callback
     * BUG #8: Price update callback can cause desync
     */
    function updatePriceWithCallback(uint256 newPrice, address callback) external {
        uint256 oldPrice = lastPrice;
        
        // BUG: Callback before price update
        // During callback, getPrice() returns OLD price
        // But caller thinks new price is set
        if (callback != address(0)) {
            (bool success, ) = callback.call(
                abi.encodeWithSignature("onPriceUpdate(uint256,uint256)", oldPrice, newPrice)
            );
            require(success, "Callback failed");
        }
        
        // Price updated AFTER callback
        lastPrice = newPrice;
    }

    /**
     * @dev Batch transfer with callback per token
     * BUG #9: Multiple callbacks in loop = amplified reentrancy
     */
    function batchSafeTransfer(
        address from,
        address to,
        uint256[] calldata tokenIds
    ) external {
        require(msg.sender == from, "Not authorized");
        
        for (uint i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            require(tokenOwner[tokenId] == from, "Not owner");
            
            // Update owner
            tokenOwner[tokenId] = to;
            
            // BUG: Callback per token = multiple reentry points
            if (to.code.length > 0) {
                require(
                    IERC721Receiver(to).onERC721Received(from, from, tokenId, "") ==
                    IERC721Receiver.onERC721Received.selector,
                    "Unsafe recipient"
                );
            }
        }
        
        // Balances updated AFTER all callbacks
        balances[from] -= tokenIds.length;
        balances[to] += tokenIds.length;
    }

    /**
     * @dev Deposit ETH to reward pool
     */
    function depositRewards() external payable {
        rewardPool += msg.value;
    }

    /**
     * @dev View function - seems safe but used during reentrancy
     */
    function userShare(address user) external view returns (uint256) {
        if (totalSupply == 0) return 0;
        return (balances[user] * 10000) / totalSupply; // Basis points
    }

    receive() external payable {}
}
