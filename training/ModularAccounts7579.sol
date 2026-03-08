// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ModularAccounts7579
 * @dev Training Contract #53 - ERC-7579 Modular Smart Account Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Validator Module Bypass (MOD-VALIDATOR-01)
 * 2. Executor Privilege Escalation (MOD-EXECUTOR-01)
 * 3. Fallback Handler Hijack (MOD-FALLBACK-01)
 * 4. Hook Bypass via Direct Call (MOD-HOOKBYPASS-01)
 * 5. Module Install Replay (MOD-INSTALL-REPLAY-01)
 * 6. Session Key Overpermission (MOD-SESSION-01)
 * 7. Recovery Module Social Engineering (MOD-RECOVERY-01)
 * 8. Delegate Action Context Confusion (MOD-DELEGATE-01)
 * 9. Module Uninstall Leaves State (MOD-UNINSTALL-01)
 * 10. Batch Execution Atomicity Break (MOD-BATCH-01)
 * 11. ERC-4337 EntryPoint Trust (MOD-ENTRYPOINT-01)
 * 12. Paymaster Drain via Module (MOD-PAYMASTER-01)
 * 13. Cross-Account Module Pollution (MOD-XACCOUNT-01)
 * 14. Time-Range Validator Expired Use (MOD-TIMERANGE-01)
 * 15. Nested Delegatecall via Module (MOD-NESTDELEG-01)
 * 16. UserOp Hash Malleability (MOD-UOPHASH-01)
 * 17. Module Type Confusion (MOD-TYPECONF-01)
 * 18. Threshold Validator DoS (MOD-THRESHOLD-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): MOD-*, account abstraction, session key
 * - Engine 2 (deep-semantic): validator logic, module install
 * - Engine 5 (reentrancy-checker): fallback handler reentrancy
 * - Engine 6 (proxy-analyzer): delegatecall patterns
 */

interface IEntryPoint {
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
    function handleOps(UserOperation[] calldata ops, address beneficiary) external;
}

contract ModularSmartAccount {
    // Module types
    uint256 constant TYPE_VALIDATOR = 1;
    uint256 constant TYPE_EXECUTOR = 2;
    uint256 constant TYPE_FALLBACK = 3;
    uint256 constant TYPE_HOOK = 4;

    struct ModuleInfo {
        bool installed;
        uint256 moduleType;
        bytes config;
    }

    mapping(address => ModuleInfo) public modules;
    mapping(bytes4 => address) public fallbackHandlers;
    address public entryPoint;
    address public owner;
    
    // Session keys
    struct SessionKey {
        address key;
        uint48 validAfter;
        uint48 validUntil;
        address[] allowedTargets;
        uint256 spendLimit;
        uint256 spent;
        bool active;
    }
    mapping(address => SessionKey) public sessionKeys;
    
    // Recovery
    mapping(address => bool) public guardians;
    uint256 public recoveryThreshold;
    uint256 public recoveryDelay;
    mapping(bytes32 => uint256) public recoveryRequests;

    // Hooks
    address[] public preExecutionHooks;
    address[] public postExecutionHooks;

    // Validator threshold
    address[] public validators;
    uint256 public validatorThreshold;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
        owner = msg.sender;
    }

    // ========== VULN 1: Validator Module Bypass (MOD-VALIDATOR-01) ==========

    // BUG #1: validateUserOp short-circuits if signature length is 0
    function validateUserOp(
        IEntryPoint.UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        require(msg.sender == entryPoint, "not entryPoint");
        
        // VULN: empty signature passes validation—intended for "self-call"
        // but entryPoint sends all ops through this function
        if (userOp.signature.length == 0) {
            return 0; // valid! should only work for internal calls
        }

        // Normal validation with installed validator module
        address validator = address(bytes20(userOp.signature[:20]));
        require(modules[validator].installed, "validator not installed");
        require(modules[validator].moduleType == TYPE_VALIDATOR, "not validator");
        
        // Forward to validator module
        (bool ok, bytes memory result) = validator.staticcall(
            abi.encodeWithSignature("validateSignature(bytes32,bytes)", userOpHash, userOp.signature[20:])
        );
        require(ok && abi.decode(result, (bool)), "invalid sig");
        
        return 0;
    }

    // ========== VULN 2: Executor Privilege Escalation (MOD-EXECUTOR-01) ==========

    // BUG #2: executor module can call any target, including installing new modules
    function executeFromModule(address target, uint256 value, bytes calldata data) external {
        require(modules[msg.sender].installed, "not installed");
        require(modules[msg.sender].moduleType == TYPE_EXECUTOR, "not executor");
        // VULN: executor can call installModule to add malicious validator
        // escalating from executor to full account control
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "execution failed");
    }

    // ========== VULN 3: Fallback Handler Hijack (MOD-FALLBACK-01) ==========

    // BUG #3: fallback handler receives delegatecall in account context
    fallback() external payable {
        address handler = fallbackHandlers[msg.sig];
        if (handler != address(0)) {
            // VULN: delegatecall gives handler full access to account storage
            // malicious handler can drain funds, change owner, etc.
            assembly {
                calldatacopy(0, 0, calldatasize())
                let result := delegatecall(gas(), handler, 0, calldatasize(), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }
    }

    // ========== VULN 4: Hook Bypass via Direct Call (MOD-HOOKBYPASS-01) ==========

    // BUG #4: hooks only run through execute(), direct calls bypass them
    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == entryPoint || msg.sender == owner, "not authorized");
        _runPreHooks(data);
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "exec failed");
        _runPostHooks(data);
    }

    // VULN: executeFromModule (above) skips hooks entirely
    // executor module operates without any hook oversight

    // ========== VULN 5: Module Install Replay (MOD-INSTALL-REPLAY-01) ==========

    // BUG #5: no nonce on module install, same install tx can be replayed
    function installModule(uint256 moduleType, address module, bytes calldata config) external {
        require(msg.sender == owner || msg.sender == entryPoint || msg.sender == address(this), "not auth");
        // VULN: no replay protection, previously uninstalled module
        // can be re-installed without owner's explicit consent
        // if original install tx is re-submitted
        modules[module] = ModuleInfo({
            installed: true,
            moduleType: moduleType,
            config: config
        });
        if (moduleType == TYPE_FALLBACK) {
            bytes4 selector = bytes4(config[:4]);
            fallbackHandlers[selector] = module;
        }
        if (moduleType == TYPE_VALIDATOR) {
            validators.push(module);
        }
    }

    // ========== VULN 6: Session Key Overpermission (MOD-SESSION-01) ==========

    // BUG #6: session key with overly broad permissions
    function createSessionKey(
        address key,
        uint48 validUntil,
        address[] calldata allowedTargets,
        uint256 spendLimit
    ) external {
        require(msg.sender == owner, "not owner");
        // VULN: if allowedTargets is empty, interpreted as "all targets allowed"
        // owner accidentally creates unrestricted session key
        sessionKeys[key] = SessionKey({
            key: key,
            validAfter: uint48(block.timestamp),
            validUntil: validUntil,
            allowedTargets: allowedTargets,
            spendLimit: spendLimit,
            spent: 0,
            active: true
        });
    }

    function executeWithSessionKey(address target, uint256 value, bytes calldata data) external {
        SessionKey storage sk = sessionKeys[msg.sender];
        require(sk.active, "inactive");
        require(block.timestamp >= sk.validAfter && block.timestamp <= sk.validUntil, "expired");
        
        // VULN: empty allowedTargets = unrestricted
        if (sk.allowedTargets.length > 0) {
            bool found = false;
            for (uint256 i = 0; i < sk.allowedTargets.length; i++) {
                if (sk.allowedTargets[i] == target) found = true;
            }
            require(found, "target not allowed");
        }
        // No target check if array empty!
        
        sk.spent += value;
        require(sk.spent <= sk.spendLimit, "spend limit");
        (bool ok, ) = target.call{value: value}(data);
        require(ok);
    }

    // ========== VULN 7: Recovery Module Social Engineering (MOD-RECOVERY-01) ==========

    // BUG #7: recovery only needs guardian signatures, susceptible to social engineering
    function initiateRecovery(address newOwner) external {
        require(guardians[msg.sender], "not guardian");
        bytes32 reqHash = keccak256(abi.encode(newOwner, block.timestamp));
        // VULN: single guardian can initiate, other guardians just need to approve
        // social engineering: convince guardians new owner is legitimate
        recoveryRequests[reqHash] = block.timestamp;
    }

    function executeRecovery(bytes32 reqHash, address newOwner, bytes[] calldata sigs) external {
        require(block.timestamp >= recoveryRequests[reqHash] + recoveryDelay, "delay");
        // VULN: doesn't verify signatures correspond to unique guardians
        // same guardian can sign multiple times
        require(sigs.length >= recoveryThreshold, "not enough sigs");
        owner = newOwner; // Account takeover
    }

    // ========== VULN 8: Delegate Action Context Confusion (MOD-DELEGATE-01) ==========

    // BUG #8: executeDelegateCall passes account context to external contract
    function executeDelegateCall(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        // VULN: delegatecall to arbitrary target with account's storage context
        // if target has selfdestruct or storage writes, account is compromised
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // ========== VULN 9: Module Uninstall Leaves State (MOD-UNINSTALL-01) ==========

    // BUG #9: uninstalling module doesn't clean up its state in account storage
    function uninstallModule(uint256 moduleType, address module) external {
        require(msg.sender == owner || msg.sender == address(this), "not auth");
        // VULN: only marks as not installed, doesn't clear config or related state
        modules[module].installed = false;
        // Fallback handler NOT removed
        // Session keys from module NOT revoked
        // Validators NOT removed from array
    }

    // ========== VULN 10: Batch Execution Atomicity Break (MOD-BATCH-01) ==========

    struct Execution {
        address target;
        uint256 value;
        bytes data;
    }

    // BUG #10: batch execution with try/catch, partial failure leaves state inconsistent
    function executeBatch(Execution[] calldata executions) external {
        require(msg.sender == entryPoint || msg.sender == owner, "not auth");
        for (uint256 i = 0; i < executions.length; i++) {
            // VULN: one failure doesn't revert entire batch
            // attacker relies on partial execution
            (bool ok, ) = executions[i].target.call{value: executions[i].value}(executions[i].data);
            // Silently continues on failure—state partially updated
        }
    }

    // ========== VULN 11: ERC-4337 EntryPoint Trust (MOD-ENTRYPOINT-01) ==========

    // BUG #11: account trusts entryPoint for all operations
    // if entryPoint is compromised or has a bug, account is fully compromised
    function getEntryPoint() external view returns (address) {
        // VULN: no way to change entryPoint if vulnerability is found
        // immutable trust in a single external contract
        return entryPoint;
    }

    // ========== VULN 12: Paymaster Drain via Module (MOD-PAYMASTER-01) ==========

    mapping(address => uint256) public paymasterDeposits;

    // BUG #12: malicious module causes account to generate expensive UserOps
    // draining the paymaster's deposit
    function drainPaymaster(address paymaster, uint256 loops) external {
        // VULN: if called through executor module, generates N expensive ops
        // each charged to the paymaster
        for (uint256 i = 0; i < loops; i++) {
            // Expensive computation billed to paymaster
            keccak256(abi.encode(block.timestamp, i, msg.sender));
        }
        // Paymaster deposit depleted
    }

    // ========== VULN 13: Cross-Account Module Pollution (MOD-XACCOUNT-01) ==========

    // BUG #13: same module instance shared across multiple accounts
    // state in module contract leaks between accounts
    function queryModuleState(address module) external view returns (bytes memory) {
        // VULN: module's storage is shared, not per-account
        // account A's configuration visible to account B
        (bool ok, bytes memory data) = module.staticcall(abi.encodeWithSignature("getState()"));
        if (ok) return data;
        return "";
    }

    // ========== VULN 14: Time-Range Validator Expired Use (MOD-TIMERANGE-01) ==========

    // BUG #14: expired session key can still be used if validator doesn't re-check time
    function validateWithTimeRange(bytes32 userOpHash, bytes calldata sig) external view returns (bool) {
        address signer = _recoverSigner(userOpHash, sig);
        SessionKey storage sk = sessionKeys[signer];
        // VULN: returns packed validAfter/validUntil but EntryPoint may not enforce
        // some bundlers don't check time-range validity
        return sk.active;
        // Missing: block.timestamp >= sk.validAfter && block.timestamp <= sk.validUntil
    }

    // ========== VULN 15: Nested Delegatecall via Module (MOD-NESTDELEG-01) ==========

    // BUG #15: module does delegatecall → target does delegatecall → arbitrary code
    function moduleProxy(address module, bytes calldata data) external {
        require(modules[module].installed, "not installed");
        // VULN: nested delegatecall chain
        // account → delegatecall → module → delegatecall → attacker → sstore
        (bool ok, ) = module.delegatecall(data);
        require(ok);
    }

    // ========== VULN 16: UserOp Hash Malleability (MOD-UOPHASH-01) ==========

    // BUG #16: UserOp hash doesn't include chain ID in some implementations
    function computeUserOpHash(IEntryPoint.UserOperation calldata userOp) external view returns (bytes32) {
        // VULN: missing chain ID—same UserOp valid on multiple chains
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            userOp.callData
            // Missing: block.chainid, address(entryPoint)
        ));
    }

    // ========== VULN 17: Module Type Confusion (MOD-TYPECONF-01) ==========

    // BUG #17: module registered as validator but called as executor
    function callModuleAsType(address module, uint256 asType, bytes calldata data) external {
        require(modules[module].installed, "not installed");
        // VULN: doesn't verify module's actual type matches requested type
        // validator module called as executor gets execution permissions
        if (asType == TYPE_EXECUTOR) {
            (bool ok, ) = module.call(data);
            require(ok);
        }
    }

    // ========== VULN 18: Threshold Validator DoS (MOD-THRESHOLD-01) ==========

    // BUG #18: M-of-N validator where one validator going offline blocks all ops
    function validateThreshold(bytes32 hash, bytes[] calldata sigs) external view returns (bool) {
        uint256 validCount = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            // VULN: if validator module reverts (DoS), entire validation fails
            // one malicious validator bricks the account
            (bool ok, bytes memory result) = validators[i].staticcall(
                abi.encodeWithSignature("validate(bytes32,bytes)", hash, sigs[i])
            );
            if (ok && abi.decode(result, (bool))) validCount++;
        }
        return validCount >= validatorThreshold;
    }

    // ========== Helpers ==========

    function _runPreHooks(bytes calldata data) internal {
        for (uint256 i = 0; i < preExecutionHooks.length; i++) {
            (bool ok, ) = preExecutionHooks[i].call(abi.encodeWithSignature("preCheck(bytes)", data));
            require(ok, "pre-hook failed");
        }
    }

    function _runPostHooks(bytes calldata data) internal {
        for (uint256 i = 0; i < postExecutionHooks.length; i++) {
            (bool ok, ) = postExecutionHooks[i].call(abi.encodeWithSignature("postCheck(bytes)", data));
            // VULN: post-hook failure silently ignored
        }
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        return ecrecover(hash, v, r, s);
    }

    function addGuardian(address g) external { require(msg.sender == owner); guardians[g] = true; }
    function setRecoveryConfig(uint256 threshold, uint256 delay) external { 
        require(msg.sender == owner); recoveryThreshold = threshold; recoveryDelay = delay; 
    }
    function addHook(address hook, bool isPre) external {
        require(msg.sender == owner);
        if (isPre) preExecutionHooks.push(hook);
        else postExecutionHooks.push(hook);
    }
    function setValidatorThreshold(uint256 t) external { require(msg.sender == owner); validatorThreshold = t; }

    receive() external payable {}
}
