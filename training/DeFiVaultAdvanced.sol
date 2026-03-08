// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DeFiVaultAdvanced
 * @dev Training Contract #33 - DeFi / Vault / Staking Advanced Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Flashloan Reward Manipulation (DEFI-ADV-01)
 * 2. LP Share Dilution (DEFI-ADV-02)
 * 3. Pool Depletion Exploit (DEFI-ADV-03)
 * 4. Yield Farming Reward Overflow (DEFI-ADV-04)
 * 5. Locked Vault Exploitation (DEFI-ADV-05)
 * 6. Multi-Vault Cross-Call Reentrancy (DEFI-ADV-06)
 * 7. Fee Misallocation in Pool (DEFI-ADV-07)
 * 8. Unchecked Reward Multiplier (DEFI-ADV-08)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): DEFI-ADV-01→08
 * - Engine 5 (economic-drift-detector): share dilution, fee leakage
 * - Engine 12 (precision-collapse-finder): reward overflow
 * - Engine 15 (composability-checker): cross-vault callbacks
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// ========== VULN 1: Flashloan Reward Manipulation (DEFI-ADV-01) ==========

contract FlashloanRewardVault {
    IERC20 public stakingToken;
    IERC20 public rewardToken;

    mapping(address => uint256) public staked;
    uint256 public totalStaked;
    uint256 public rewardPerToken;
    uint256 public lastRewardTime;
    uint256 public rewardRate = 1e18;

    constructor(address _staking, address _reward) {
        stakingToken = IERC20(_staking);
        rewardToken = IERC20(_reward);
        lastRewardTime = block.timestamp;
    }

    function updateReward() internal {
        if (totalStaked > 0) {
            rewardPerToken += rewardRate * (block.timestamp - lastRewardTime) * 1e18 / totalStaked;
        }
        lastRewardTime = block.timestamp;
    }

    // BUG #1: flashloan → stake → trigger reward distribution → unstake
    // Reward distributed pro-rata on momentary balance
    function stake(uint256 amount) external {
        updateReward();
        stakingToken.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
        totalStaked += amount;
        // VULN: no minimum lock period, no snapshot-based reward
    }

    function unstake(uint256 amount) external {
        updateReward();
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        stakingToken.transfer(msg.sender, amount);
    }

    function claimReward() external {
        updateReward();
        uint256 reward = staked[msg.sender] * rewardPerToken / 1e18;
        rewardToken.transfer(msg.sender, reward);
    }
}

// ========== VULN 2: LP Share Dilution (DEFI-ADV-02) ==========

contract DilutablePool {
    IERC20 public token;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        uint256 poolBalance = token.balanceOf(address(this));
        uint256 newShares;

        if (totalShares == 0) {
            newShares = amount;
        } else {
            newShares = amount * totalShares / poolBalance;
        }

        token.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += newShares;
        totalShares += newShares;
    }

    // BUG #2: direct donation to pool manipulates share/asset ratio
    // Attacker donates 1M tokens → totalShares stays same → share price inflated
    // Next depositor gets 0 shares due to rounding
    function withdraw(uint256 shareAmount) external {
        uint256 poolBalance = token.balanceOf(address(this));
        // VULN: poolBalance includes donations, inflating withdrawal amount
        uint256 amount = shareAmount * poolBalance / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        token.transfer(msg.sender, amount);
    }
}

// ========== VULN 3: Pool Depletion Exploit (DEFI-ADV-03) ==========

contract DepletablePool {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public constant FEE = 30; // 0.3%

    constructor(address _a, address _b) {
        tokenA = IERC20(_a);
        tokenB = IERC20(_b);
    }

    // BUG #3: small trades accumulate rounding error in one direction
    // Many small swaps drain pool via fee/rounding asymmetry
    function swap(address tokenIn, uint256 amountIn) external returns (uint256 amountOut) {
        bool isA = tokenIn == address(tokenA);
        uint256 resIn = isA ? reserveA : reserveB;
        uint256 resOut = isA ? reserveB : reserveA;

        uint256 amountInWithFee = amountIn * (10000 - FEE);
        // VULN: rounding always favors trader on small amounts
        amountOut = amountInWithFee * resOut / (resIn * 10000 + amountInWithFee);

        if (isA) {
            reserveA += amountIn;
            reserveB -= amountOut;
        } else {
            reserveB += amountIn;
            reserveA -= amountOut;
        }
    }
}

// ========== VULN 4: Yield Farming Reward Overflow (DEFI-ADV-04) ==========

contract OverflowYieldFarm {
    mapping(address => uint256) public userStake;
    mapping(address => uint256) public userRewardDebt;
    uint256 public accRewardPerShare;
    uint256 public rewardRate = 100e18;
    uint256 public lastBlock;
    uint256 public totalStaked;

    // BUG #4: rewardRate * elapsed * userStake overflows with large values
    function pendingReward(address user) external view returns (uint256) {
        uint256 elapsed = block.number - lastBlock;
        // VULN: rewardRate * elapsed can overflow for long durations
        uint256 newReward = rewardRate * elapsed;
        uint256 newAccPerShare = accRewardPerShare + newReward * 1e12 / totalStaked;
        return userStake[user] * newAccPerShare / 1e12 - userRewardDebt[user];
    }
}

// ========== VULN 5: Locked Vault Exploitation (DEFI-ADV-05) ==========

contract LockedVault {
    mapping(address => uint256) public lockedAmount;
    mapping(address => uint256) public unlockTime;
    mapping(address => uint256) public lockDuration;
    address public admin;

    constructor() { admin = msg.sender; }

    function lock(uint256 amount, uint256 duration) external {
        lockedAmount[msg.sender] += amount;
        unlockTime[msg.sender] = block.timestamp + duration;
        lockDuration[msg.sender] = duration;
    }

    // BUG #5: admin can modify unlock parameters retroactively
    function setUnlockTime(address user, uint256 newTime) external {
        require(msg.sender == admin, "not admin");
        // VULN: can set unlockTime to past, allowing immediate withdrawal of locked funds
        unlockTime[user] = newTime;
    }

    function withdraw() external {
        require(block.timestamp >= unlockTime[msg.sender], "still locked");
        uint256 amount = lockedAmount[msg.sender];
        lockedAmount[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

// ========== VULN 6: Multi-Vault Cross-Call Reentrancy (DEFI-ADV-06) ==========

contract VaultA {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // BUG #6: external call to VaultB during withdrawal allows reentrancy
    function withdrawToVault(address vaultB, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // VULN: external call before state update — callback from VaultB
        // can re-enter this function
        token.transfer(vaultB, amount); // callback if token has hooks
        VaultB(vaultB).deposit(msg.sender, amount);
        balances[msg.sender] -= amount; // updated AFTER external calls
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }
}

contract VaultB {
    mapping(address => uint256) public balances;

    function deposit(address user, uint256 amount) external {
        balances[user] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

// ========== VULN 7: Fee Misallocation in Pool (DEFI-ADV-07) ==========

contract FeePool {
    mapping(address => uint256) public lpShares;
    uint256 public totalLPShares;
    uint256 public accumulatedFees;
    mapping(address => uint256) public lastFeesClaimed;

    // BUG #7: fees distributed based on current shares, not time-weighted
    function claimFees() external {
        uint256 userShare = lpShares[msg.sender];
        // VULN: new LP who just deposited gets same fee share as long-term LP
        // No time-weighting or snapshot mechanism
        uint256 totalFees = accumulatedFees - lastFeesClaimed[msg.sender];
        uint256 userFees = totalFees * userShare / totalLPShares;
        lastFeesClaimed[msg.sender] = accumulatedFees;
        payable(msg.sender).transfer(userFees);
    }

    function addLiquidity() external payable {
        lpShares[msg.sender] += msg.value;
        totalLPShares += msg.value;
    }
}

// ========== VULN 8: Unchecked Reward Multiplier (DEFI-ADV-08) ==========

contract UncappedMultiplierFarm {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public multiplier;
    uint256 public baseRewardRate = 1e18;
    address public admin;

    constructor() { admin = msg.sender; }

    // BUG #8: multiplier without cap allows infinite inflation
    function setMultiplier(address user, uint256 mult) external {
        require(msg.sender == admin, "not admin");
        // VULN: no maximum cap on multiplier
        multiplier[user] = mult;
    }

    function calculateReward(address user) external view returns (uint256) {
        // baseRewardRate * staked * multiplier — if multiplier is huge,
        // reward exceeds total token supply
        return staked[user] * baseRewardRate * multiplier[user] / 1e18;
    }
}
