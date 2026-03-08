// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AccountAbstractionVuln
 * @dev Training Contract #18 - ERC-4337 Account Abstraction Vulnerabilities (2025/2026)
 * 
 * CUTTING EDGE VULNERABILITIES:
 * 1. Bundler front-running - bundler extracts MEV from UserOps
 * 2. Paymaster drain - sponsor infinite gas
 * 3. Signature aggregation collision - multiple wallets, one sig
 * 4. EntryPoint reentrancy - callback during validation
 * 5. UserOp hash malleability
 * 6. Validation vs execution gas mismatch
 * 
 * REAL-WORLD EXAMPLES:
 * - Biconomy bundler MEV reports 2024
 * - Pimlico paymaster audit findings
 * - ERC-4337 v0.6 EntryPoint reentrancy
 * 
 * CROSS-CONTRACT CHAINS:
 * - Links to 06_CallbackReentrancy (wallet callbacks)
 * - Links to 12_DirtyHigherBits (signature manipulation)
 * - Links to 02_AuthorityChain (delegate wallets)
 * - Links to 07_FlashLoanVictim (flash loan via UserOp)
 * 
 * ENGINES THAT SHOULD DETECT:
 * - Engine 13: MEV (bundler extraction)
 * - Engine 11: CallerMyth (msg.sender in AA)
 * - Engine 1: Pattern (signature checks)
 */

// 🔗 CHAIN: Interfaces to existing contracts
interface ICallbackReentrancy {
    function safeMint(address to, bytes calldata data) external;
}

interface IDirtyHigherBits {
    function verifySignature(bytes32 hash, bytes calldata signature) external view returns (bool);
}

interface IAuthorityChain {
    function isDelegate(address account, address delegate) external view returns (bool);
    function executeAsDelegate(address target, bytes calldata data) external;
}

interface IFlashLoanVictim {
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external;
}

/**
 * @dev ERC-4337 UserOperation structure
 */
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

/**
 * @dev Paymaster interface
 */
interface IPaymaster {
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);
    
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external;
}

enum PostOpMode {
    opSucceeded,
    opReverted,
    postOpReverted
}

contract AccountAbstractionVuln {
    // === AA STATE ===
    
    // EntryPoint state
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public deposits;
    
    // Paymaster state
    mapping(address => uint256) public paymasterDeposits;
    mapping(address => uint256) public paymasterStakes;
    uint256 public constant PAYMASTER_STAKE_DELAY = 1 days;
    
    // Bundler state
    address public trustedBundler;
    mapping(address => bool) public allowedBundlers;
    
    // 🔗 CHAIN: External dependencies
    ICallbackReentrancy public callbackReentrancy;
    IDirtyHigherBits public signatureHelper;
    IAuthorityChain public authorityChain;
    IFlashLoanVictim public flashLoanVictim;
    
    // Aggregator state (for BLS)
    mapping(address => bool) public registeredAggregators;
    
    // Reentrancy guard
    bool private _executing;
    
    event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, bool success);
    event Deposited(address indexed account, uint256 amount);
    event PaymasterSponsored(address indexed paymaster, address indexed sender, uint256 cost);
    event BundlerRegistered(address indexed bundler);

    constructor() {
        trustedBundler = msg.sender;
    }
    
    function setExternalContracts(
        address _callbackReentrancy,
        address _signatureHelper,
        address _authorityChain,
        address _flashLoanVictim
    ) external {
        callbackReentrancy = ICallbackReentrancy(_callbackReentrancy);
        signatureHelper = IDirtyHigherBits(_signatureHelper);
        authorityChain = IAuthorityChain(_authorityChain);
        flashLoanVictim = IFlashLoanVictim(_flashLoanVictim);
    }

    // ========== ENTRYPOINT ==========
    
    /**
     * @dev Handle single UserOperation
     * 
     * BUG #1: No MEV protection
     * Bundler sees UserOp, can front-run the trade inside
     */
    function handleOp(UserOperation calldata op) external {
        // BUG #1: Bundler is msg.sender, sees op.callData
        // Can extract MEV by front-running the actual trade
        
        bytes32 userOpHash = _getUserOpHash(op);
        
        // Validate
        uint256 validationData = _validateUserOp(op, userOpHash);
        require(validationData == 0, "Invalid signature");
        
        // BUG #2: Nonce check happens AFTER validation
        // Reentrancy during validation can replay
        require(nonces[op.sender] == op.nonce, "Invalid nonce");
        nonces[op.sender]++;
        
        // Execute
        _executing = true;
        (bool success, ) = op.sender.call{gas: op.callGasLimit}(op.callData);
        _executing = false;
        
        emit UserOperationEvent(userOpHash, op.sender, success);
    }
    
    /**
     * @dev Handle batch of UserOperations
     * 
     * BUG #3: Bundler reordering within batch
     * Can order ops to extract maximum MEV
     */
    function handleOps(UserOperation[] calldata ops) external {
        // BUG #3: Bundler controls order of ops
        // Op[0] = victim's swap, Op[1] = bundler's front-run
        // Bundler reorders: [bundler front-run, victim, bundler back-run]
        
        for (uint256 i = 0; i < ops.length; i++) {
            bytes32 userOpHash = _getUserOpHash(ops[i]);
            
            uint256 validationData = _validateUserOp(ops[i], userOpHash);
            if (validationData != 0) continue; // Skip invalid
            
            if (nonces[ops[i].sender] != ops[i].nonce) continue;
            nonces[ops[i].sender]++;
            
            _executing = true;
            (bool success, ) = ops[i].sender.call{gas: ops[i].callGasLimit}(ops[i].callData);
            _executing = false;
            
            emit UserOperationEvent(userOpHash, ops[i].sender, success);
        }
    }
    
    /**
     * @dev Validate UserOperation signature
     * 
     * BUG #4: Signature malleability not checked
     * BUG #5: No replay protection across chains
     */
    function _validateUserOp(
        UserOperation calldata op,
        bytes32 userOpHash
    ) internal returns (uint256) {
        // BUG #5: userOpHash doesn't include chainId!
        // Same UserOp valid on mainnet and fork
        
        // BUG #4: Signature can be malleable (s-value)
        // ECDSA allows two valid signatures for same message
        
        // Check signature using wallet's validate function
        // Or use signatureHelper (which has dirty bits bug)
        if (address(signatureHelper) != address(0)) {
            // 🔗 CHAIN: Uses DirtyHigherBits which has malleability!
            if (!signatureHelper.verifySignature(userOpHash, op.signature)) {
                return 1; // Invalid
            }
        }
        
        return 0; // Valid
    }
    
    function _getUserOpHash(UserOperation calldata op) internal view returns (bytes32) {
        // BUG #5: No chainId in hash!
        return keccak256(abi.encode(
            op.sender,
            op.nonce,
            keccak256(op.initCode),
            keccak256(op.callData),
            op.callGasLimit,
            op.verificationGasLimit,
            op.preVerificationGas,
            op.maxFeePerGas,
            op.maxPriorityFeePerGas,
            keccak256(op.paymasterAndData)
            // Missing: block.chainid, address(this)
        ));
    }

    // ========== PAYMASTER ==========
    
    /**
     * @dev Validate with paymaster sponsorship
     * 
     * BUG #6: Paymaster can be drained by malicious UserOps
     * No limit on gas sponsorship per user
     */
    function handleOpWithPaymaster(UserOperation calldata op) external {
        require(op.paymasterAndData.length >= 20, "No paymaster");
        
        address paymaster = address(bytes20(op.paymasterAndData[:20]));
        
        // BUG #6: No per-user limit!
        // Attacker creates 1000 accounts, each drains paymaster
        uint256 maxCost = op.callGasLimit * op.maxFeePerGas;
        
        require(paymasterDeposits[paymaster] >= maxCost, "Paymaster underfunded");
        
        bytes32 userOpHash = _getUserOpHash(op);
        
        // Call paymaster validation
        (bytes memory context, uint256 validationData) = IPaymaster(paymaster)
            .validatePaymasterUserOp(op, userOpHash, maxCost);
        
        require(validationData == 0, "Paymaster rejected");
        
        // BUG #7: Deduct before execution
        // If execution fails, paymaster still pays
        paymasterDeposits[paymaster] -= maxCost;
        
        // Execute
        nonces[op.sender]++;
        (bool success, ) = op.sender.call{gas: op.callGasLimit}(op.callData);
        
        // Refund unused gas (but calculation is wrong)
        // BUG #8: Refund uses tx.gasprice, not op.maxFeePerGas
        uint256 actualCost = (op.callGasLimit - gasleft()) * tx.gasprice;
        uint256 refund = maxCost - actualCost;
        
        // BUG: refund could be > maxCost if gasprice < maxFeePerGas
        // This would underflow or give wrong refund
        paymasterDeposits[paymaster] += refund;
        
        // PostOp
        try IPaymaster(paymaster).postOp(
            success ? PostOpMode.opSucceeded : PostOpMode.opReverted,
            context,
            actualCost
        ) {} catch {
            // BUG #9: If postOp reverts, funds still deducted
        }
        
        emit PaymasterSponsored(paymaster, op.sender, actualCost);
    }
    
    /**
     * @dev Deposit to paymaster
     */
    function depositToPaymaster(address paymaster) external payable {
        paymasterDeposits[paymaster] += msg.value;
    }

    // ========== SIGNATURE AGGREGATION ==========
    
    /**
     * @dev Handle aggregated signatures (BLS)
     * 
     * BUG #10: Aggregation collision
     * Two different ops could have same aggregated signature
     */
    function handleAggregatedOps(
        UserOperation[] calldata ops,
        bytes calldata aggregatedSignature,
        address aggregator
    ) external {
        require(registeredAggregators[aggregator], "Unknown aggregator");
        
        // BUG #10: Aggregator could be malicious
        // Returns true for any signature if colluding with attacker
        
        // BUG #11: Same aggregated sig for different op sets
        // If hash collision in BLS, different ops validate same
        
        // Simplified: just check aggregator is registered
        // Real implementation would verify BLS signature
        
        for (uint256 i = 0; i < ops.length; i++) {
            // Skip individual signature check, trust aggregator
            nonces[ops[i].sender]++;
            
            _executing = true;
            ops[i].sender.call{gas: ops[i].callGasLimit}(ops[i].callData);
            _executing = false;
        }
    }
    
    function registerAggregator(address aggregator) external {
        // BUG #12: Anyone can register aggregator!
        registeredAggregators[aggregator] = true;
    }

    // ========== ENTRYPOINT REENTRANCY ==========
    
    /**
     * @dev Simulate validation for estimation
     * 
     * BUG #13: Reentrancy during simulation
     * Wallet's validateUserOp can call back into EntryPoint
     */
    function simulateValidation(UserOperation calldata op) external {
        // BUG #13: Not using reentrancy guard!
        // Wallet can call handleOp during simulation
        
        // This is view-like but actually modifies state
        uint256 gasStart = gasleft();
        
        // Call wallet's validateUserOp
        (bool success, bytes memory result) = op.sender.call(
            abi.encodeWithSignature(
                "validateUserOp((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes),bytes32,uint256)",
                op,
                _getUserOpHash(op),
                0 // missingAccountFunds
            )
        );
        
        // BUG #14: If wallet is malicious, it can:
        // 1. Call back handleOp with different UserOp
        // 2. Drain deposits
        // 3. Modify nonces
        
        uint256 gasUsed = gasStart - gasleft();
        
        // Return gas estimation (but state was modified!)
        require(success, string(result));
    }

    // ========== CROSS-CONTRACT ATTACKS ==========
    
    /**
     * @dev Execute UserOp that calls CallbackReentrancy
     * 🔗 CHAIN: AccountAbstraction → CallbackReentrancy → AccountAbstraction
     */
    function executeWithCallback(
        UserOperation calldata op,
        address callbackTarget,
        bytes calldata callbackData
    ) external {
        bytes32 userOpHash = _getUserOpHash(op);
        
        // Validate
        _validateUserOp(op, userOpHash);
        nonces[op.sender]++;
        
        // Execute main op
        op.sender.call{gas: op.callGasLimit}(op.callData);
        
        // BUG #15: Callback during execution
        // 🔗 CHAIN: CallbackReentrancy will call back!
        if (address(callbackReentrancy) != address(0)) {
            callbackReentrancy.safeMint(op.sender, callbackData);
            // safeMint has callback → can reenter this contract
        }
    }
    
    /**
     * @dev Execute UserOp with flash loan
     * 🔗 CHAIN: AccountAbstraction → FlashLoanVictim
     */
    function executeWithFlashLoan(
        UserOperation calldata op,
        uint256 flashAmount
    ) external {
        // BUG #16: Flash loan inside UserOp execution
        // 🔗 CHAIN: FlashLoanVictim's callback can manipulate AA state
        
        bytes32 userOpHash = _getUserOpHash(op);
        _validateUserOp(op, userOpHash);
        nonces[op.sender]++;
        
        if (address(flashLoanVictim) != address(0)) {
            flashLoanVictim.flashLoan(
                op.sender,
                flashAmount,
                op.callData
            );
        }
    }
    
    /**
     * @dev Execute as delegate wallet
     * 🔗 CHAIN: AuthorityChain → AccountAbstraction
     */
    function executeAsDelegate(
        address wallet,
        UserOperation calldata op
    ) external {
        // BUG #17: Uses AuthorityChain which has transitive delegation!
        // Delegate's delegate can execute for original wallet
        
        if (address(authorityChain) != address(0)) {
            require(
                authorityChain.isDelegate(wallet, msg.sender),
                "Not delegate"
            );
        }
        
        // Execute op on behalf of wallet
        // BUG: Nonce is for wallet, not delegate
        // Delegate can replay if wallet hasn't acted
        nonces[wallet]++;
        
        wallet.call{gas: op.callGasLimit}(op.callData);
    }

    // ========== GAS MANIPULATION ==========
    
    /**
     * @dev Estimate gas for UserOp
     * 
     * BUG #18: Gas estimation can differ from execution
     * Wallet returns different gas during estimate vs execute
     */
    function estimateUserOpGas(UserOperation calldata op) external returns (uint256) {
        // BUG #18: Wallet can detect estimation mode
        // Return low gas → get included
        // Use high gas → DoS bundler
        
        uint256 gasStart = gasleft();
        
        // Simulate validation + execution
        _validateUserOp(op, _getUserOpHash(op));
        op.sender.call{gas: op.callGasLimit}(op.callData);
        
        return gasStart - gasleft();
    }

    receive() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
}

/**
 * @dev Malicious wallet that exploits AA
 */
contract MaliciousAAWallet {
    AccountAbstractionVuln public entryPoint;
    bool public inSimulation;
    
    function validateUserOp(
        UserOperation calldata,
        bytes32,
        uint256
    ) external returns (uint256) {
        // BUG: Detect if in simulation mode
        if (tx.origin == address(0)) {
            inSimulation = true;
            // Return success, use low gas
        }
        
        // During real execution, do expensive ops
        if (!inSimulation) {
            // Drain paymaster
            // Reenter EntryPoint
            // etc
        }
        
        return 0; // Valid
    }
    
    receive() external payable {}
}
