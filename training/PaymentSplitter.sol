// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PaymentSplitter
 * @dev Training Contract #65 - Payment Splitting & Revenue Distribution Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Push vs Pull Payment Griefing (PAY-PUSHPULL-01)
 * 2. Share Dilution Attack (PAY-DILUTE-01)
 * 3. Rounding Dust Accumulation (PAY-ROUNDING-01)
 * 4. ETH vs ERC20 Desync (PAY-ETHDESYNC-01)
 * 5. Reentrancy on Release (PAY-REENTER-01)
 * 6. Zero-Share Recipient DoS (PAY-ZEROSHARE-01)
 * 7. Dynamic Share Manipulation (PAY-DYNSHARE-01)
 * 8. Revenue Timing Exploit (PAY-TIMING-01)
 * 9. Multi-Token Revenue Confusion (PAY-MULTITOKEN-01)
 * 10. Royalty Split Bypass (PAY-ROYALTYBYPASS-01)
 * 11. Gas Limit on Mass Payout (PAY-GASLIMIT-01)
 * 12. Unclaimed Fund Expiry (PAY-UNCLAIMED-01)
 * 13. Flash Loan Share Acquisition (PAY-FLASHSHARE-01)
 * 14. Delegatecall Payment Theft (PAY-DELEGATETHEFT-01)
 * 15. Percentage Sum Overflow (PAY-PERCENTOVERFLOW-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): PAY-*, payment, split, revenue, shares, distribute
 * - Engine 2 (deep-semantic): distribution logic, accounting
 * - Engine 13 (mev-analyzer): flash loan acquisition, timing
 * - Engine 3 (state-desync): ETH/ERC20 balance desync, rounding
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract AdvancedPaymentSplitter {

    struct Payee {
        address account;
        uint256 shares;
        uint256 totalReleased;
        uint256 lastClaimTime;
    }

    Payee[] public payees;
    mapping(address => uint256) public payeeIndex;
    mapping(address => bool) public isPayee;
    
    uint256 public totalShares;
    uint256 public totalReleased;
    uint256 public totalReceived;
    
    // ERC20 tracking
    mapping(address => uint256) public erc20TotalReleased;
    mapping(address => mapping(address => uint256)) public erc20Released;
    
    address public owner;
    bool public locked;
    uint256 public expiryPeriod = 365 days;

    constructor(address[] memory _payees, uint256[] memory _shares) {
        require(_payees.length == _shares.length, "length mismatch");
        owner = msg.sender;
        for (uint256 i = 0; i < _payees.length; i++) {
            _addPayee(_payees[i], _shares[i]);
        }
    }

    // ========== VULN 1: Push vs Pull Payment Griefing (PAY-PUSHPULL-01) ==========

    // BUG #1: push payment to all payees — one reverting recipient blocks all
    function distributeAll() external {
        uint256 balance = address(this).balance;
        for (uint256 i = 0; i < payees.length; i++) {
            uint256 payment = balance * payees[i].shares / totalShares;
            // VULN: if any payee is a contract that reverts on receive,
            // entire distribution fails
            (bool ok, ) = payees[i].account.call{value: payment}("");
            require(ok, "transfer failed");
            payees[i].totalReleased += payment;
        }
        totalReleased += balance;
    }

    // ========== VULN 2: Share Dilution Attack (PAY-DILUTE-01) ==========

    // BUG #2: owner adds new payee, diluting existing payees
    function addPayee(address account, uint256 shares_) external {
        require(msg.sender == owner, "not owner");
        // VULN: no consent from existing payees
        // owner adds 99% share recipient, existing payees diluted to ~1%
        _addPayee(account, shares_);
    }

    // ========== VULN 3: Rounding Dust Accumulation (PAY-ROUNDING-01) ==========

    // BUG #3: integer division leaves dust that accumulates forever
    function release(address account) external {
        require(isPayee[account], "not payee");
        uint256 totalReceived_ = address(this).balance + totalReleased;
        Payee storage p = payees[payeeIndex[account]];
        
        uint256 owed = totalReceived_ * p.shares / totalShares - p.totalReleased;
        // VULN: rounding error means sum(owed) < totalReceived_
        // dust accumulates and is locked forever
        // with 100 payees and micro-payments, significant funds locked
        require(owed > 0, "nothing owed");
        
        p.totalReleased += owed;
        p.lastClaimTime = block.timestamp;
        totalReleased += owed;
        
        (bool ok, ) = account.call{value: owed}("");
        require(ok, "transfer failed");
    }

    // ========== VULN 4: ETH vs ERC20 Desync (PAY-ETHDESYNC-01) ==========

    // BUG #4: ETH and ERC20 tracked separately but share ratios affect both
    function releaseERC20(address token, address account) external {
        require(isPayee[account], "not payee");
        
        uint256 tokenBalance = IERC20(token).balanceOf(address(this));
        uint256 totalReceived_ = tokenBalance + erc20TotalReleased[token];
        Payee storage p = payees[payeeIndex[account]];
        
        uint256 owed = totalReceived_ * p.shares / totalShares - erc20Released[token][account];
        // VULN: share change between ETH and ERC20 claims causes desync
        // adding a payee changes shares but doesn't retroactively adjust ERC20 claims
        require(owed > 0, "nothing owed");
        
        erc20Released[token][account] += owed;
        erc20TotalReleased[token] += owed;
        IERC20(token).transfer(account, owed);
    }

    // ========== VULN 5: Reentrancy on Release (PAY-REENTER-01) ==========

    // BUG #5: ETH release with callback before state update
    function releaseUnsafe(address payable account) external {
        Payee storage p = payees[payeeIndex[account]];
        uint256 totalReceived_ = address(this).balance + totalReleased;
        uint256 owed = totalReceived_ * p.shares / totalShares - p.totalReleased;
        
        // VULN: ETH sent BEFORE state update → reentrancy
        (bool ok, ) = account.call{value: owed}("");
        require(ok);
        // State update after external call
        p.totalReleased += owed;
        totalReleased += owed;
    }

    // ========== VULN 6: Zero-Share Recipient DoS (PAY-ZEROSHARE-01) ==========

    // BUG #6: payee with 0 shares causes division issues
    function _addPayee(address account, uint256 shares_) internal {
        // VULN: no check for shares_ > 0
        // zero-share payee makes distributeAll send 0 ETH calls, wasting gas
        require(!isPayee[account], "duplicate");
        payeeIndex[account] = payees.length;
        payees.push(Payee(account, shares_, 0, 0));
        isPayee[account] = true;
        totalShares += shares_;
    }

    // ========== VULN 7: Dynamic Share Manipulation (PAY-DYNSHARE-01) ==========

    // BUG #7: shares modifiable after revenue accumulation
    function updateShares(address account, uint256 newShares) external {
        require(msg.sender == owner, "not owner");
        Payee storage p = payees[payeeIndex[account]];
        
        // VULN: updating shares affects past unclaimed revenue
        // increase share before claiming → get higher portion of historical revenue
        totalShares = totalShares - p.shares + newShares;
        p.shares = newShares;
    }

    // ========== VULN 8: Revenue Timing Exploit (PAY-TIMING-01) ==========

    // BUG #8: claim right before big payment arrives, claim again after
    function canDoubleDip(address account) external view returns (bool) {
        Payee storage p = payees[payeeIndex[account]];
        uint256 totalReceived_ = address(this).balance + totalReleased;
        uint256 owed = totalReceived_ * p.shares / totalShares - p.totalReleased;
        // VULN: if they claim now (owed > 0), then another payment comes in,
        // they effectively get fresh calculation — not really double-dip
        // but timing between releases can be exploited with share manipulation
        return owed > 0;
    }

    // ========== VULN 9: Multi-Token Revenue Confusion (PAY-MULTITOKEN-01) ==========

    // BUG #9: same contract receives ETH, USDC, WETH — different claim states
    function claimAllTokens(address[] calldata tokens) external {
        address account = msg.sender;
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == address(0)) {
                this.release(account);
            } else {
                this.releaseERC20(tokens[i], account);
            }
        }
        // VULN: if any claim fails (e.g., 0 owed for one token), entire batch reverts
        // each token has independent "owed" calculation
    }

    // ========== VULN 10: Royalty Split Bypass (PAY-ROYALTYBYPASS-01) ==========

    mapping(address => bool) public royaltyExempt;

    // BUG #10: NFT marketplace royalty payments to this splitter
    // but some marketplaces bypass royalties entirely
    function receiveRoyalty(uint256 salePrice, uint256 royaltyBps) external payable {
        // VULN: expected = salePrice * royaltyBps / 10000
        // actual msg.value may be 0 if marketplace doesn't enforce royalties
        // no verification that msg.value matches expected royalty
        totalReceived += msg.value;
    }

    // ========== VULN 11: Gas Limit on Mass Payout (PAY-GASLIMIT-01) ==========

    // BUG #11: distributeAll loops over all payees
    function distributeToRange(uint256 from, uint256 to) external {
        uint256 balance = address(this).balance;
        require(to <= payees.length, "out of range");
        for (uint256 i = from; i < to; i++) {
            uint256 payment = balance * payees[i].shares / totalShares;
            // VULN: if payees.length > 1000, even batched distribution exceeds block gas
            // with complex recipient contracts, gas per transfer varies wildly
            (bool ok, ) = payees[i].account.call{value: payment, gas: 2300}("");
            // Using 2300 gas stipend — fails for contracts that need more
            if (!ok) {} // Silently skips failed transfers
        }
    }

    // ========== VULN 12: Unclaimed Fund Expiry (PAY-UNCLAIMED-01) ==========

    // BUG #12: unclaimed funds redistributed after expiry
    function expireUnclaimed(address account) external {
        Payee storage p = payees[payeeIndex[account]];
        require(block.timestamp > p.lastClaimTime + expiryPeriod, "not expired");
        
        // VULN: owner can expire inactive payee's unclaimed funds
        // funds go back to pool, benefiting active payees (including owner)
        uint256 totalReceived_ = address(this).balance + totalReleased;
        uint256 owed = totalReceived_ * p.shares / totalShares - p.totalReleased;
        
        // Mark as claimed even though funds go to owner
        p.totalReleased += owed;
        totalReleased += owed;
        // Funds stay in contract, effectively redistributed
    }

    // ========== VULN 13: Flash Loan Share Acquisition (PAY-FLASHSHARE-01) ==========

    // BUG #13: share tokens represent payment rights, flash-borrowable
    mapping(address => uint256) public shareTokenBalance;

    function transferShares(address to, uint256 amount) external {
        Payee storage p = payees[payeeIndex[msg.sender]];
        require(p.shares >= amount, "insufficient shares");
        
        // VULN: transfer shares → claim revenue → transfer shares back
        // flash loan shares for one block, claim accumulated revenue
        p.shares -= amount;
        payees[payeeIndex[to]].shares += amount;
    }

    // ========== VULN 14: Delegatecall Payment Theft (PAY-DELEGATETHEFT-01) ==========

    // BUG #14: if splitter is used as implementation for proxy, delegatecall context
    function executeAction(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        // VULN: owner can call arbitrary contract with delegatecall
        // in proxy context, can transfer all funds out
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // ========== VULN 15: Percentage Sum Overflow (PAY-PERCENTOVERFLOW-01) ==========

    // BUG #15: shares can be set such that totalShares overflows
    function addPayeeBatch(address[] calldata accounts, uint256[] calldata shares_) external {
        require(msg.sender == owner, "not owner");
        for (uint256 i = 0; i < accounts.length; i++) {
            // VULN: no check that totalShares fits in uint256
            // with enough payees at max shares, totalShares overflows
            _addPayee(accounts[i], shares_[i]);
        }
    }

    // ========== View & Admin ==========

    function pendingPayment(address account) external view returns (uint256) {
        Payee storage p = payees[payeeIndex[account]];
        uint256 totalReceived_ = address(this).balance + totalReleased;
        return totalReceived_ * p.shares / totalShares - p.totalReleased;
    }

    function payeeCount() external view returns (uint256) {
        return payees.length;
    }

    receive() external payable {
        totalReceived += msg.value;
    }
}
