// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ArithmeticAccessDoS
 * @dev Training Contract #29 - Arithmetic Overflow + Access Control + DoS Patterns
 *
 * VULNERABILITY CATEGORIES:
 * 1. Vesting Release Overflow (ARITH-ADV-01)
 * 2. Timelock Reward Overflow (ARITH-ADV-02)
 * 3. Staking Bonus Multiplier Overflow (ARITH-ADV-03)
 * 4. Batch Withdraw Underflow (ARITH-ADV-04)
 * 5. Role Hierarchy Bypass (ACCESS-ADV-01)
 * 6. Role Enumeration Bug (ACCESS-ADV-02)
 * 7. Role-Dependent Reward Bypass (ACCESS-ADV-03)
 * 8. Batch Payout DoS (DOS-ADV-01)
 * 9. Oracle Outage DoS (DOS-ADV-02)
 * 10. ERC1155 Batch Hooks DoS (DOS-ADV-03)
 * 11. NFT Marketplace Settlement DoS (DOS-ADV-04)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): ARITH-ADV-*, ACCESS-ADV-*, DOS-ADV-*
 * - Engine 12 (precision-collapse-finder): overflow in vesting/reward calc
 * - Engine 6 (authority-chain-mapper): role hierarchy bypass
 * - Engine 8 (negative-space-finder): missing role checks
 */

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IERC1155Receiver {
    function onERC1155BatchReceived(
        address operator, address from, uint256[] calldata ids,
        uint256[] calldata values, bytes calldata data
    ) external returns (bytes4);
}

// ========== VULNS 1-4: Arithmetic Advanced ==========

contract ArithmeticVulns {
    // VULN 1: vestingAmount * elapsed / duration can overflow
    struct VestingSchedule {
        uint256 totalAmount;
        uint256 startTime;
        uint256 duration;
        uint256 claimed;
    }

    mapping(address => VestingSchedule) public vestingSchedules;

    function createVesting(address beneficiary, uint256 amount, uint256 duration) external {
        vestingSchedules[beneficiary] = VestingSchedule({
            totalAmount: amount,
            startTime: block.timestamp,
            duration: duration,
            claimed: 0
        });
    }

    // BUG #1: vestingAmount * elapsed can overflow with large values
    function claimVested() external {
        VestingSchedule storage schedule = vestingSchedules[msg.sender];
        uint256 elapsed = block.timestamp - schedule.startTime;
        // VULN: totalAmount * elapsed overflows before division
        uint256 vested = schedule.totalAmount * elapsed / schedule.duration;
        uint256 claimable = vested - schedule.claimed;
        schedule.claimed = vested;
        // transfer claimable...
    }

    // VULN 2: rewardRate * lockDuration unbounded
    mapping(address => uint256) public stakedAmount;
    mapping(address => uint256) public lockDuration;
    uint256 public rewardRate = 1e18;

    function calculateReward(address user) public view returns (uint256) {
        // BUG #2: rewardRate * lockDuration can overflow
        return stakedAmount[user] * rewardRate * lockDuration[user] / 365 days;
    }

    // VULN 3: staking bonus multiplier uncapped
    mapping(address => uint256) public bonusMultiplier;

    function setBonus(address user, uint256 multiplier) external {
        // BUG #3: no cap on multiplier — can be set to type(uint256).max
        bonusMultiplier[user] = multiplier;
    }

    function calculateBonusReward(address user) public view returns (uint256) {
        // baseReward * bonusMultiplier overflows
        return stakedAmount[user] * rewardRate * bonusMultiplier[user];
    }

    // VULN 4: batch withdraw underflow
    function batchWithdraw(uint256[] calldata amounts) external {
        uint256 balance = stakedAmount[msg.sender];
        for (uint256 i = 0; i < amounts.length; i++) {
            // BUG #4: balance checked once but decremented in loop
            // if sum of amounts > balance, later iterations underflow
            balance -= amounts[i]; // underflow on later iterations
            // transfer amounts[i]...
        }
        stakedAmount[msg.sender] = balance;
    }
}

// ========== VULNS 5-7: Access Control Advanced ==========

contract AccessControlVulns {
    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(bytes32 => bytes32) public roleAdmin;
    mapping(bytes32 => address[]) internal _roleMembers;
    mapping(bytes32 => mapping(address => uint256)) internal _roleMemberIndex;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR");

    address public proxy; // upgradeable proxy reference

    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public rewardEligible;

    // VULN 5: role hierarchy bypassed via proxy context
    // BUG: In proxy context, storage layout differs — roleAdmin mapping
    // points to wrong slot, allowing OPERATOR to act as ADMIN
    function grantRole(bytes32 role, address account) external {
        require(roles[roleAdmin[role]][msg.sender], "not admin of role");
        roles[role][account] = true;
        _roleMembers[role].push(account);
        _roleMemberIndex[role][account] = _roleMembers[role].length - 1;
    }

    // VULN 6: Role enumeration not updated on revoke
    function revokeRole(bytes32 role, address account) external {
        require(roles[roleAdmin[role]][msg.sender], "not admin");
        roles[role][account] = false;
        // BUG #6: _roleMembers array NOT updated — getRoleMemberCount returns stale count
        // _roleMemberIndex NOT cleared, getRoleMember returns revoked addresses
    }

    function getRoleMemberCount(bytes32 role) external view returns (uint256) {
        return _roleMembers[role].length; // includes revoked members
    }

    function getRoleMember(bytes32 role, uint256 index) external view returns (address) {
        return _roleMembers[role][index]; // may return revoked member
    }

    // VULN 7: reward claimed after role revoked
    function distributeRewards() external {
        require(roles[MANAGER_ROLE][msg.sender], "not manager");
        // BUG #7: check eligibility, then distribute — but between these two steps,
        // role can be revoked. User already marked eligible captures reward.
        rewardEligible[msg.sender] = true;
    }

    function claimReward() external {
        // No re-check of role — only checks rewardEligible flag set before revoke
        require(rewardEligible[msg.sender], "not eligible");
        uint256 reward = pendingRewards[msg.sender];
        rewardEligible[msg.sender] = false;
        pendingRewards[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }
}

// ========== VULNS 8-11: DoS Advanced ==========

contract DoSVulns {
    address[] public payees;
    mapping(address => uint256) public shares;
    IOracle public oracle;
    bool public oracleAvailable = true;
    mapping(address => uint256) public deposits;

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
    }

    // VULN 8: single revert in payout loop blocks all
    function distributePayouts() external {
        // BUG #8: if ANY recipient reverts, entire batch fails
        // Malicious payee deploys contract with reverting receive()
        for (uint256 i = 0; i < payees.length; i++) {
            uint256 amount = shares[payees[i]];
            if (amount > 0) {
                shares[payees[i]] = 0;
                // One revert blocks everyone
                (bool ok,) = payees[i].call{value: amount}("");
                require(ok, "payout failed");
            }
        }
    }

    // VULN 9: oracle outage blocks all operations
    function deposit(address token, uint256 amount) external {
        // BUG #9: if oracle is offline, getPrice reverts, blocking ALL deposits
        uint256 price = oracle.getPrice(token); // reverts if oracle down
        require(price > 0, "invalid price");
        deposits[msg.sender] += amount * price / 1e18;
    }

    // VULN 10: ERC1155 batch hooks gas exhaustion
    function safeBatchTransfer(
        address to, uint256[] calldata ids, uint256[] calldata values
    ) external {
        // BUG #10: unbounded array in onERC1155BatchReceived causes gas exhaustion
        // Attacker passes thousands of ids/values, receiver hook runs out of gas
        for (uint256 i = 0; i < ids.length; i++) {
            // ... transfer logic
        }
        IERC1155Receiver(to).onERC1155BatchReceived(msg.sender, msg.sender, ids, values, "");
    }

    // VULN 11: NFT marketplace settlement DoS
    struct Listing {
        address seller;
        uint256 price;
        address royaltyRecipient;
        uint256 royaltyBps;
        address feeRecipient;
        uint256 feeBps;
    }

    mapping(uint256 => Listing) public listings;

    function settleSale(uint256 tokenId) external payable {
        Listing memory listing = listings[tokenId];
        require(msg.value >= listing.price, "underpaid");

        // BUG #11: royalty recipient can be contract that reverts, blocking sale
        uint256 royalty = listing.price * listing.royaltyBps / 10000;
        (bool r1,) = listing.royaltyRecipient.call{value: royalty}("");
        require(r1, "royalty failed"); // DoS if recipient reverts

        uint256 fee = listing.price * listing.feeBps / 10000;
        (bool r2,) = listing.feeRecipient.call{value: fee}("");
        require(r2, "fee failed"); // DoS if fee recipient reverts

        uint256 sellerAmount = listing.price - royalty - fee;
        (bool r3,) = listing.seller.call{value: sellerAmount}("");
        require(r3, "seller failed");
    }
}
