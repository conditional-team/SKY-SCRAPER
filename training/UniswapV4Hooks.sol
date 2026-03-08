// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title UniswapV4Hooks
 * @dev Training Contract #46 - Uniswap V4 Hook Exploits
 *
 * VULNERABILITY CATEGORIES:
 * 1. Hook Reentrancy via beforeSwap (HOOK-REENTER-01)
 * 2. Hook Reentrancy via afterSwap (HOOK-REENTER-02)
 * 3. Hook Callback Data Injection (HOOK-INJECT-01)
 * 4. Dynamic Fee Manipulation (HOOK-FEE-01)
 * 5. Fee Siphon via Hook Override (HOOK-FEE-02)
 * 6. Pool Initialization Front-run (HOOK-INIT-01)
 * 7. Tick Manipulation via Hook (HOOK-TICK-01)
 * 8. Liquidity Snipe on addLiquidity Hook (HOOK-LIQ-01)
 * 9. Hook Permission Bitmap Spoof (HOOK-PERM-01)
 * 10. Flash Accounting Desync (HOOK-FLASH-01)
 * 11. Delta Resolution Underflow (HOOK-DELTA-01)
 * 12. Singleton Storage Collision (HOOK-STORAGE-01)
 * 13. Hook Return Value Manipulation (HOOK-RET-01)
 * 14. Cross-Pool Hook State Leak (HOOK-XPOOL-01)
 * 15. beforeDonate Griefing (HOOK-DONATE-01)
 * 16. ERC-6909 Claim Theft (HOOK-CLAIM-01)
 * 17. Nested Pool Key Confusion (HOOK-KEY-01)
 * 18. NoOp Swap Accounting Bypass (HOOK-NOOP-01)
 * 19. Transient Storage Hook Leak (HOOK-TSTORE-01)
 * 20. Hook Self-Destruct Rug (HOOK-SELFDESTRUCT-01)
 *
 * ENGINES THAT SHOULD DETECT:
 * - Engine 1 (pattern-db): HOOK-*, reentrancy, fee manipulation
 * - Engine 2 (deep-semantic): delta resolution, flash accounting
 * - Engine 13 (mev-analyzer): MEV via hook fee, tick manipulation
 * - Engine 17 (cross-contract): cross-pool state, singleton collision
 */

interface IPoolManager {
    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
    struct SwapParams {
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
    }
    struct ModifyLiquidityParams {
        int24 tickLower;
        int24 tickUpper;
        int256 liquidityDelta;
        bytes32 salt;
    }
    function swap(PoolKey calldata key, SwapParams calldata params, bytes calldata hookData) external returns (int256, int256);
    function modifyLiquidity(PoolKey calldata key, ModifyLiquidityParams calldata params, bytes calldata hookData) external returns (int256, int256);
    function donate(PoolKey calldata key, uint256 amount0, uint256 amount1, bytes calldata hookData) external returns (int256, int256);
    function take(address currency, address to, uint256 amount) external;
    function settle(address currency) external returns (uint256);
}

// ========== VULN 1: Hook Reentrancy via beforeSwap (HOOK-REENTER-01) ==========
// ========== VULN 2: Hook Reentrancy via afterSwap (HOOK-REENTER-02) ==========

contract MaliciousSwapHook {
    IPoolManager public poolManager;
    bool public attacking;
    uint256 public stolenAmount;

    constructor(address _pm) { poolManager = IPoolManager(_pm); }

    // BUG #1: beforeSwap callback re-enters the pool manager to do another swap
    // draining pool reserves by manipulating price between nested swaps
    function beforeSwap(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4) {
        if (!attacking) {
            attacking = true;
            // VULN: reentrancy into poolManager during swap callback
            IPoolManager.SwapParams memory reverseParams = IPoolManager.SwapParams({
                zeroForOne: !params.zeroForOne,
                amountSpecified: params.amountSpecified / 2,
                sqrtPriceLimitX96: 0
            });
            poolManager.swap(key, reverseParams, "");
            attacking = false;
        }
        return bytes4(0x00000001);
    }

    // BUG #2: afterSwap re-enters to take() extra tokens from delta resolution
    function afterSwap(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        int256 delta0,
        int256 delta1,
        bytes calldata hookData
    ) external returns (bytes4) {
        // VULN: re-enter take() to steal unsettled deltas
        if (delta0 > 0) {
            poolManager.take(key.currency0, address(this), uint256(delta0));
            stolenAmount += uint256(delta0);
        }
        return bytes4(0x00000002);
    }
}

// ========== VULN 3: Hook Callback Data Injection (HOOK-INJECT-01) ==========

contract DataInjectionHook {
    mapping(address => bool) public whitelisted;

    // BUG #3: hookData is user-controlled, hook trusts decoded addresses from it
    // Attacker encodes arbitrary beneficiary address in hookData
    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata,
        IPoolManager.SwapParams calldata,
        bytes calldata hookData
    ) external returns (bytes4) {
        // VULN: trusting user-supplied hookData without validation
        (address beneficiary, uint256 discount) = abi.decode(hookData, (address, uint256));
        whitelisted[beneficiary] = true; // attacker injects own address
        return bytes4(0x00000001);
    }
}

// ========== VULN 4: Dynamic Fee Manipulation (HOOK-FEE-01) ==========
// ========== VULN 5: Fee Siphon via Hook Override (HOOK-FEE-02) ==========

contract DynamicFeeHook {
    uint24 public baseFee = 3000; // 0.3%
    mapping(address => uint24) public customFees;
    address public feeRecipient;
    uint256 public siphonedFees;

    constructor(address _recipient) { feeRecipient = _recipient; }

    // BUG #4: fee can be set to 0 for specific addresses, enabling free swaps
    // that sandwich other users' trades
    function setCustomFee(address user, uint24 fee) external {
        // VULN: no access control, anyone can set fee to 0 for themselves
        customFees[user] = fee;
    }

    function getFee(address sender) external view returns (uint24) {
        if (customFees[sender] > 0) return customFees[sender];
        return baseFee;
    }

    // BUG #5: hook overrides fee to route portion to hook deployer
    function afterSwap(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        int256 delta0,
        int256,
        bytes calldata
    ) external returns (bytes4) {
        // VULN: hook silently takes a cut of every swap
        if (delta0 > 0) {
            uint256 hookCut = uint256(delta0) * 5 / 100; // 5% hidden fee
            siphonedFees += hookCut;
        }
        return bytes4(0x00000002);
    }
}

// ========== VULN 6: Pool Initialization Front-run (HOOK-INIT-01) ==========

contract PoolInitHook {
    mapping(bytes32 => address) public poolCreators;
    mapping(bytes32 => uint160) public initialPrices;

    // BUG #6: pool initialization can be front-run to set attacker-favorable price
    // first initializer controls the starting sqrtPriceX96
    function beforeInitialize(
        address sender,
        IPoolManager.PoolKey calldata key,
        uint160 sqrtPriceX96,
        bytes calldata
    ) external returns (bytes4) {
        bytes32 poolId = keccak256(abi.encode(key));
        // VULN: no check if pool was already intended by legitimate deployer
        // first caller wins, can set extreme initial price
        poolCreators[poolId] = sender;
        initialPrices[poolId] = sqrtPriceX96;
        return bytes4(0x00000003);
    }
}

// ========== VULN 7: Tick Manipulation via Hook (HOOK-TICK-01) ==========

contract TickManipHook {
    mapping(bytes32 => int24) public lastTick;
    
    // BUG #7: hook artificially constrains tick range, creating MEV opportunity
    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata
    ) external returns (bytes4) {
        bytes32 poolId = keccak256(abi.encode(key));
        // VULN: hook can revert on certain tick ranges forcing price into narrow band
        // enabling precise sandwich attacks
        int24 currentTick = lastTick[poolId];
        if (currentTick > 1000 || currentTick < -1000) {
            revert("tick out of hook range"); // artificial constraint
        }
        return bytes4(0x00000001);
    }

    function afterSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        int256,
        int256,
        bytes calldata hookData
    ) external returns (bytes4) {
        bytes32 poolId = keccak256(abi.encode(key));
        // Store manipulated tick
        if (hookData.length >= 32) {
            lastTick[poolId] = abi.decode(hookData, (int24));
        }
        return bytes4(0x00000002);
    }
}

// ========== VULN 8: Liquidity Snipe on addLiquidity Hook (HOOK-LIQ-01) ==========

contract LiquiditySniperHook {
    IPoolManager public poolManager;
    bool private sniping;

    constructor(address _pm) { poolManager = IPoolManager(_pm); }

    // BUG #8: beforeAddLiquidity front-runs LP by adding own liquidity first
    // then removes after the LP's tx, capturing the trading fees
    function beforeAddLiquidity(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata
    ) external returns (bytes4) {
        if (!sniping && sender != address(this)) {
            sniping = true;
            // VULN: JIT liquidity via hook callback
            IPoolManager.ModifyLiquidityParams memory sniperParams = IPoolManager.ModifyLiquidityParams({
                tickLower: params.tickLower,
                tickUpper: params.tickUpper,
                liquidityDelta: params.liquidityDelta * 10, // 10x the user's liquidity
                salt: bytes32(0)
            });
            poolManager.modifyLiquidity(key, sniperParams, "");
            sniping = false;
        }
        return bytes4(0x00000004);
    }
}

// ========== VULN 9: Hook Permission Bitmap Spoof (HOOK-PERM-01) ==========

contract PermissionSpoofHook {
    // BUG #9: hook address doesn't match required permission bits
    // In V4, hook permissions are encoded in the address itself
    // deployer uses CREATE2 to mine address with extra permission bits

    // VULN: hook claims permissions it shouldn't have by mining address
    // e.g., sets beforeSwap + afterSwap + beforeDonate bits
    // but actually implements malicious logic in those callbacks

    uint256 public constant BEFORE_SWAP_FLAG = 1 << 159;
    uint256 public constant AFTER_SWAP_FLAG = 1 << 158;
    uint256 public constant BEFORE_DONATE_FLAG = 1 << 153;

    function getHookPermissions() external pure returns (uint256) {
        // Returns permissions that may not match actual address bits
        return BEFORE_SWAP_FLAG | AFTER_SWAP_FLAG | BEFORE_DONATE_FLAG;
    }
}

// ========== VULN 10: Flash Accounting Desync (HOOK-FLASH-01) ==========
// ========== VULN 11: Delta Resolution Underflow (HOOK-DELTA-01) ==========

contract FlashAccountingHook {
    IPoolManager public poolManager;
    mapping(address => int256) public pendingDeltas;

    constructor(address _pm) { poolManager = IPoolManager(_pm); }

    // BUG #10: hook manipulates flash accounting by taking tokens
    // without properly settling the debt
    function afterSwap(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        int256 delta0,
        int256 delta1,
        bytes calldata
    ) external returns (bytes4) {
        // VULN: take tokens but skip settle, leaving pool manager with bad debt
        if (delta0 < 0) {
            poolManager.take(key.currency0, address(this), uint256(-delta0));
            // Missing: poolManager.settle(key.currency0);
        }
        return bytes4(0x00000002);
    }

    // BUG #11: delta can underflow when hook processes concurrent operations
    function processDeltas(address user, int256 amount) external {
        // VULN: unchecked arithmetic on delta, can underflow to huge positive
        unchecked {
            pendingDeltas[user] -= amount; // underflow if amount > pendingDeltas[user]
        }
    }
}

// ========== VULN 12: Singleton Storage Collision (HOOK-STORAGE-01) ==========

contract SingletonCollisionHook {
    // In V4, PoolManager is a singleton holding all pools
    // BUG #12: hook uses storage slots that may collide with other hooks
    // in the same singleton context

    // VULN: predictable storage slots can be manipulated by other hooks
    mapping(bytes32 => uint256) public hookState; // slot collision risk

    function storeState(bytes32 poolId, uint256 value) external {
        // No isolation between hook instances—shared singleton storage namespace
        hookState[poolId] = value;
    }

    // Different pool can overwrite same slot if poolId collides
    function readState(bytes32 poolId) external view returns (uint256) {
        return hookState[poolId];
    }
}

// ========== VULN 13: Hook Return Value Manipulation (HOOK-RET-01) ==========

contract ReturnValueHook {
    // BUG #13: hook returns crafted bytes4 selector to bypass PoolManager checks
    // V4 validates return selectors, but hook can return wrong selector
    // to skip fee charging or delta resolution

    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata,
        IPoolManager.SwapParams calldata,
        bytes calldata hookData
    ) external pure returns (bytes4) {
        // VULN: dynamically choosing return value to manipulate pool behavior
        if (hookData.length > 0) {
            return bytes4(hookData[:4]); // attacker controls return selector
        }
        return bytes4(0x00000001);
    }
}

// ========== VULN 14: Cross-Pool Hook State Leak (HOOK-XPOOL-01) ==========

contract CrossPoolHook {
    struct PoolState {
        uint256 totalVolume;
        int24 lastTick;
        uint256 feesCollected;
    }
    mapping(bytes32 => PoolState) public poolStates;

    // BUG #14: same hook instance used across multiple pools leaks state
    // attacker monitors pool A's state via hook to frontrun pool B
    function afterSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        int256 delta0,
        int256,
        bytes calldata
    ) external returns (bytes4) {
        bytes32 poolId = keccak256(abi.encode(key));
        // VULN: oracle data from one pool visible to all pool users
        poolStates[poolId].totalVolume += delta0 > 0 ? uint256(delta0) : uint256(-delta0);
        return bytes4(0x00000002);
    }

    // Public view leaks cross-pool intel
    function getPoolVolume(bytes32 poolId) external view returns (uint256) {
        return poolStates[poolId].totalVolume;
    }
}

// ========== VULN 15: beforeDonate Griefing (HOOK-DONATE-01) ==========

contract DonateGriefHook {
    mapping(address => bool) public blocked;

    // BUG #15: hook blocks legitimate donate() calls, griefing protocol incentives
    function beforeDonate(
        address sender,
        IPoolManager.PoolKey calldata,
        uint256,
        uint256,
        bytes calldata
    ) external returns (bytes4) {
        // VULN: censorship via hook—blocks specific senders from donating
        require(!blocked[sender], "blocked by hook");
        return bytes4(0x00000005);
    }

    function blockSender(address user) external {
        // No access control
        blocked[user] = true;
    }
}

// ========== VULN 16: ERC-6909 Claim Theft (HOOK-CLAIM-01) ==========

contract ClaimTheftHook {
    IPoolManager public poolManager;
    mapping(address => uint256) public claimBalances;

    constructor(address _pm) { poolManager = IPoolManager(_pm); }

    // BUG #16: hook mints ERC-6909 claims to itself instead of the actual LP
    function afterAddLiquidity(
        address sender,
        IPoolManager.PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata params,
        int256 delta0,
        int256 delta1,
        bytes calldata
    ) external returns (bytes4) {
        // VULN: claims credited to hook, not to sender
        if (delta0 > 0) {
            claimBalances[address(this)] += uint256(delta0); // should be sender
        }
        return bytes4(0x00000006);
    }
}

// ========== VULN 17: Nested Pool Key Confusion (HOOK-KEY-01) ==========

contract PoolKeyConfusionHook {
    // BUG #17: hook re-uses incoming PoolKey to operate on a DIFFERENT pool
    // by modifying fee or tickSpacing, creating confusion in accounting
    IPoolManager public poolManager;
    constructor(address _pm) { poolManager = IPoolManager(_pm); }

    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata
    ) external returns (bytes4) {
        // VULN: modify the key to reference different pool silently
        IPoolManager.PoolKey memory fakeKey = IPoolManager.PoolKey({
            currency0: key.currency0,
            currency1: key.currency1,
            fee: key.fee + 1, // different pool!
            tickSpacing: key.tickSpacing,
            hooks: key.hooks
        });
        // Swap on wrong pool, causing accounting mismatch
        poolManager.swap(fakeKey, params, "");
        return bytes4(0x00000001);
    }
}

// ========== VULN 18: NoOp Swap Accounting Bypass (HOOK-NOOP-01) ==========

contract NoOpHook {
    // BUG #18: hook returns NoOp signal to skip actual swap
    // but PoolManager still processes delta resolution
    // attacker exploits stale deltas from previous operations

    mapping(bytes32 => int256) public staleDelta;

    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        bytes calldata hookData
    ) external returns (bytes4) {
        bytes32 poolId = keccak256(abi.encode(key));
        // VULN: store delta, return NoOp, then claim stale delta later
        if (hookData.length > 0 && hookData[0] == 0x01) {
            return bytes4(0xFFFFFFFF); // NoOp signal
        }
        return bytes4(0x00000001);
    }
}

// ========== VULN 19: Transient Storage Hook Leak (HOOK-TSTORE-01) ==========

contract TransientStorageHook {
    // BUG #19: hook uses transient storage (EIP-1153) for state
    // but transient storage persists within the transaction
    // subsequent operations in same tx see stale hook data

    // Simulated transient storage using regular storage (pre-Cancun)
    mapping(bytes32 => uint256) private transientSlots;
    
    function beforeSwap(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata
    ) external returns (bytes4) {
        bytes32 slot = keccak256(abi.encodePacked(sender, key.currency0));
        // VULN: transient storage from previous call in same tx leaks
        uint256 previousValue = transientSlots[slot];
        if (previousValue > 0) {
            // Stale value from earlier in tx—attacker bundles operations
            // to exploit leaked state
        }
        transientSlots[slot] = uint256(params.amountSpecified > 0 ? params.amountSpecified : -params.amountSpecified);
        return bytes4(0x00000001);
    }
}

// ========== VULN 20: Hook Self-Destruct Rug (HOOK-SELFDESTRUCT-01) ==========

contract SelfDestructHook {
    address public deployer;
    bool public active = true;

    constructor() { deployer = msg.sender; }

    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata,
        IPoolManager.SwapParams calldata,
        bytes calldata
    ) external returns (bytes4) {
        require(active, "hook dead");
        return bytes4(0x00000001);
    }

    // BUG #20: hook deployer can disable the hook, bricking all pools using it
    // V4 hooks are immutable in pool keys—no way to migrate
    function rugPull() external {
        require(msg.sender == deployer, "not deployer");
        // VULN: disabling hook bricks every pool that references this address
        active = false;
        // Even worse: selfdestruct sends ETH balance to deployer
    }

    // Deployer can also just drain any tokens accidentally sent to hook
    function drain(address token) external {
        require(msg.sender == deployer);
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", deployer, type(uint256).max));
        require(ok);
    }
}
