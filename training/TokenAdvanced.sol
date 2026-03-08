// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TokenAdvanced
 * @dev Training Contract #32 - Token / ERC Advanced Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Unlimited Allowance Abuse (TOKEN-ADV-01)
 * 2. Token Reflection Miscalc (TOKEN-ADV-02)
 * 3. Anti-Whale Bypass (TOKEN-ADV-03)
 * 4. ERC721 Metadata Overwrite (TOKEN-ADV-04)
 * 5. ERC20 Approve Front-Running (TOKEN-ADV-05)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): TOKEN-ADV-01→05
 * - Engine 2 (asset-asymmetry-checker): reflection token issues
 * - Engine 13 (mev-analyzer): approve front-running
 */

// ========== VULN 1: Unlimited Allowance Abuse (TOKEN-ADV-01) ==========

contract UnlimitedAllowanceToken {
    string public name = "UnlimitedToken";
    string public symbol = "ULTK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        // BUG #1: type(uint256).max approval persists forever
        // Common UX pattern but dangerous — approved contract can drain at any time
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        // VULN: infinite approval never decreases
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

// ========== VULN 2: Token Reflection Miscalc (TOKEN-ADV-02) ==========

contract ReflectionToken {
    string public name = "ReflectToken";
    uint256 public totalSupply;
    uint256 public totalReflections;
    uint256 public reflectionRate;
    uint256 public constant REFLECTION_FEE = 200; // 2%

    mapping(address => uint256) public reflectedBalance;
    mapping(address => bool) public isExcluded;
    address[] public excluded;

    constructor(uint256 supply) {
        totalSupply = supply;
        reflectedBalance[msg.sender] = supply * 1e18;
        reflectionRate = 1e18;
    }

    // BUG #2: reflection fee redistribution calculated incorrectly
    // Excluded addresses still affect rate calculation
    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = amount * REFLECTION_FEE / 10000;
        uint256 transferAmount = amount - fee;

        reflectedBalance[from] -= amount * reflectionRate;
        reflectedBalance[to] += transferAmount * reflectionRate;

        // VULN: fee redistributed to ALL holders including excluded ones
        // totalReflections doesn't account for excluded supply
        totalReflections += fee;
        // Rate changes but excluded balances also benefit
        reflectionRate = (totalSupply * 1e18) / (totalSupply - totalReflections);
    }

    function balanceOf(address account) external view returns (uint256) {
        if (isExcluded[account]) {
            return reflectedBalance[account] / 1e18; // wrong for excluded
        }
        return reflectedBalance[account] / reflectionRate;
    }
}

// ========== VULN 3: Anti-Whale Bypass (TOKEN-ADV-03) ==========

contract AntiWhaleToken {
    uint256 public maxTxAmount = 1000 * 1e18;
    uint256 public cooldownTime = 30;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public lastTransferTime;
    mapping(address => bool) public isExempt;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        isExempt[msg.sender] = true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (!isExempt[msg.sender]) {
            require(amount <= maxTxAmount, "exceeds max tx");
            require(
                block.timestamp >= lastTransferTime[msg.sender] + cooldownTime,
                "cooldown active"
            );
        }

        lastTransferTime[msg.sender] = block.timestamp;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        // BUG #3: anti-whale bypassed by:
        // 1. Using multiple wallets (no per-address holding limit)
        // 2. Deploying a splitter contract that distributes via transferFrom
        // 3. cooldownTime is per-sender, not per-block
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

// ========== VULN 4: ERC721 Metadata Overwrite (TOKEN-ADV-04) ==========

contract MutableMetadataNFT {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => string) public tokenURIs;
    mapping(address => uint256) public balanceOf;
    uint256 public nextTokenId;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event MetadataUpdate(uint256 tokenId, string newURI);

    function mint(string calldata uri) external returns (uint256 tokenId) {
        tokenId = nextTokenId++;
        ownerOf[tokenId] = msg.sender;
        balanceOf[msg.sender]++;
        tokenURIs[tokenId] = uri;
        emit Transfer(address(0), msg.sender, tokenId);
    }

    // BUG #4: tokenURI changeable after mint & after sale
    // Seller mints beautiful art, sells it, then changes metadata to blank
    function setTokenURI(uint256 tokenId, string calldata newUri) external {
        // VULN: only checks current owner — but previous owner set URI
        // If ownership hasn't changed, original minter can still change URI after listing
        require(ownerOf[tokenId] == msg.sender, "not owner");
        // No freeze mechanism, no event-based URI lock
        tokenURIs[tokenId] = newUri;
        emit MetadataUpdate(tokenId, newUri);
    }

    function tokenURI(uint256 tokenId) external view returns (string memory) {
        return tokenURIs[tokenId];
    }
}

// ========== VULN 5: ERC20 Approve Front-Running (TOKEN-ADV-05) ==========

contract FrontRunApproveToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }

    // BUG #5: approve(A→B) can be front-run
    // If allowance changes from 100 to 50, spender can:
    // 1. See the tx in mempool
    // 2. Front-run with transferFrom(100)
    // 3. After approve(50) mines, transferFrom(50)
    // Total spent: 150 instead of intended 50
    function approve(address spender, uint256 amount) external returns (bool) {
        // VULN: no increaseAllowance/decreaseAllowance pattern
        // Direct overwrite enables front-running race condition
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
