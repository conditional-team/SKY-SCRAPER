# Sky-Scraper Training Set — Complete Vulnerability Catalog

> **67 contracts · 1029 vulnerabilities · 75+ cross-contract chain links**

---

## 01 — PrecisionVault.sol

| # | Vulnerability |
|---|---|
| BUG #1 | First depositor can inflate share price by depositing 1 wei then donating tokens to the vault |
| BUG #2 | `deposit` uses `totalDeposited` instead of actual balance; donated tokens create ghost value |
| BUG #3 | Fee calculated on shares with precision loss (`shares * FEE_BPS / BPS`), compounding over time |
| BUG #4 | `withdraw` rounds UP (in favor of withdrawer), inconsistent with deposit rounding DOWN |
| BUG #5 | `+1` rounding always rounds up on remainder, enabling slow drain |
| BUG #6 | `virtualPrice()` diverges from `actualPrice()` because `totalDeposited` doesn't include direct donations |

---

## 02 — AuthorityChain.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Any admin can add delegates; delegates can act with admin powers (emergent privilege) |
| BUG #2 | Delegate check includes `historicalPermissions[msg.sender][msg.sig]` which is never cleared after revocation |
| BUG #3 | Pending owner transfer can be frontrun between `initiate` and `complete` |
| BUG #4 | No cancellation mechanism; pending owner can complete transfer even if current owner changed mind; old owner's admin status persists |
| BUG #5 | No limit on admin chain length; any admin adds more admins unbounded |
| BUG #6 | Delegates approved by any admin (even later-revoked), and delegates can add other delegates (transitive trust) |
| BUG #7 | Revoked delegate can still call `withdraw()` via `historicalPermissions` path |
| BUG #8 | `canWithdraw()` view function exposes that historical permissions grant access, but looks like a "safe" check |
| CHAIN BUG | `addFactoryDelegate` trusts the ADDRESS not bytecode; after selfdestruct + redeploy (metamorphic), trust and `historicalPermissions` persist for the new contract |

---

## 03 — GhostStateOracle.sol

| # | Vulnerability |
|---|---|
| BUG #1 | `cachedPrice` creates ghost state; independent of `currentPrice` until cache expires |
| BUG #2 | `historicalPrices` mapping can be used to "prove" old/favorable states |
| BUG #3 | Consumer contracts trust the oracle price, but receive stale cached values |
| BUG #4 | Competing trusted sources can set different prices (`sourcePrice`), creating conflicting "truths" |
| BUG #5 | `updatePrice()` updates `currentPrice` but NOT `cachedPrice`; ghost state lasts up to 5 minutes |
| BUG #6 | `_notifyConsumers()` sends the cached/ghost price (calls `getPrice()` which may return stale cache) |
| BUG #7 | Consumers notified with potentially stale cached price; `consumerLastKnownPrice` stores ghost value |
| BUG #8 | `getPrice()` returns `cachedPrice` if not expired; cache can be 5 min stale while `currentPrice` moved 50% |
| BUG #9 | Staleness check in `getFreshPrice()` uses `<=` instead of `<`, allowing price exactly at `MAX_STALENESS` |
| BUG #10 | `submitSourcePrice()` stores a separate price per source but doesn't update `currentPrice`; consumers get conflicting answers |
| BUG #11 | `getMedianPrice()` returns first source price, not actual median |
| BUG #12 | `proveHistoricalPrice()` lets attacker use old favorable price as "proof" |

---

## 04 — TemporalLock.sol

| # | Vulnerability |
|---|---|
| BUG #2 | `unlockTime` set via `block.timestamp` which miners can manipulate by ~15 seconds; can be in past on chain reorg |
| BUG #3 | TOCTOU: check `unlockTime`, then state changes, then transfer; exploitable window |
| BUG #4 | Cooldown uses block numbers but unlock uses timestamps; inconsistent temporal models |
| BUG #5 | Early unlock penalty calculation rounds in favor of user; penalty stays in contract and can be extracted |
| BUG #6 | Same-block creation and unlock possible; miner can include `lock()` + `unlock()` in same block |
| BUG #7 | `extendLock()` can extend to a SHORTER time if `unlockTime` already passed (resets expired lock) |
| BUG #8 | No check that new unlock time > old unlock time; `additionalDuration = 1` can still leave time in past |
| BUG #9 | `previewUnlock()` assumes current `block.timestamp`; actual unlock timestamp could differ |
| BUG #10 | `canUnlock()` returns true even if lock was created in the current block |
| BUG #11 | Penalty accumulator (`address(this).balance - totalLocked`) can be drained by owner |
| CHAIN BUG | If `transientContract.isFlashLoanActive()` returns true, all checks (cooldown, penalty) are bypassed via `fastMode` |

---

## 05 — NegativeSpaceDAO.sol

| # | Vulnerability |
|---|---|
| BUG #1 | No `cancelled` field in Proposal struct; cancelled proposals still exist in mapping |
| BUG #2 | `hasVoted` mapping entries never deleted; persist forever even after proposal cancelled |
| BUG #3 | `votingPower` only increases, never decreases |
| BUG #4 | `delegatedTo` mapping uses `uint256` instead of `address`, and is never used correctly |
| BUG #5 | `lastProposalTime` and `totalProposalsCreated` are set but never reset; false metrics |
| BUG #6 | `emergencyMode` can be set to `true` but never set back to `false` (permanent) |
| BUG #7 | Missing events for: vote, cancel, emergency mode toggle, voting power change |
| BUG #8 | `propose()` emits no event |
| BUG #9 | `lastProposalTime` and `totalProposalsCreated` only increase, creating false metrics |
| BUG #10 | `hasVoted[proposalId][voter]` set to true but never deleted on cancel; voters locked out if ID reused |
| BUG #11 | `executed = true` but proposal struct stays in mapping forever (no cleanup) |
| BUG #12 | `cancelProposal()` deletes struct but `hasVoted` mapping entries remain; old voters can't vote if proposal ID reused |
| BUG #13 | `grantVotingPower()` only adds power, never revokes |
| BUG #14 | `emergencyMode = true` is permanent; no function to disable |
| BUG #15 | `emergencyWithdraw()` does not check `transfer()` return value |
| BUG #16 | `emergencyWithdraw()` missing zero-address check on `to` |
| BUG #17 | `transfer()` return value ignored in `emergencyWithdraw()` |
| BUG #18 | `transferFrom()` return value ignored in `depositForPower()`; voting power granted even if transfer failed |

---

## 06 — CallbackReentrancy.sol

| # | Vulnerability |
|---|---|
| BUG #1 | No reentrancy guard (`_locked` commented out) |
| BUG #2 | `lastPrice` state variable read during callback returns stale value |
| BUG #3 | `safeMint()`: `tokenOwner` NOT set before callback; attacker can reenter and mint same `tokenId` again |
| BUG #4 | `burnAndClaim()`: cross-function reentrancy via `_claimRewards` which makes external call |
| BUG #5 | `_claimRewards()`: `pendingRewards[user] = 0` set AFTER `.call{value: amount}` — classic reentrancy |
| BUG #6 | `_calculateRewards()`: read-only reentrancy; during reentry `balances[user]` is inconsistent with `totalSupply` |
| BUG #7 | `getPrice()`: returns stale `lastPrice` during callback; other contracts may rely on it for pricing decisions |
| BUG #8 | `updatePriceWithCallback()`: callback executed before `lastPrice` is updated; `getPrice()` returns old value during callback |
| BUG #9 | `batchSafeTransfer()`: callback per token in loop = multiple reentry points; balances updated AFTER all callbacks |
| CHAIN BUG | If `transientContract.isFlashLoanActive()` is true, `safeMint()` becomes free (no payment required) |

---

## 07 — FlashLoanVictim.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Spot price derived from `reserveCollateral`/`reserveDebt` reserves (flash-loan manipulable) |
| BUG #2 | `lastOraclePrice` is single value with no TWAP protection |
| BUG #3 | `getPrice()` uses spot reserves, not TWAP; falls back to external manipulable oracles (`ghostOracle.cachedPrice()`, `amm.getRate()`) |
| BUG #4 | `updateOraclePrice()` sets `lastOraclePrice` from spot price; single-block update can swing price arbitrarily |
| BUG #5 | `borrow()` uses `getPrice()` (flash-manipulable) for collateral check |
| BUG #6 | `isLiquidatable()` uses same manipulable `getPrice()` |
| BUG #7 | `liquidate()` uses manipulated price, enabling attacker to seize disproportionate collateral |
| BUG #8 | Collateral-to-seize calculation in `liquidate()` uses manipulated price; 10x pump = 10x more collateral seized |
| BUG #9 | `executeFlashLoan()` has no reentrancy protection during the flash callback |
| BUG #10 | `swap()` has no real slippage protection; attacker controls `debtOut` parameter |
| CHAIN BUG | `getPrice()` falls back to `ghostOracle.cachedPrice()` (GhostStateOracle #3 stale cache) and `amm.getRate()` (SandwichableView #15 manipulable) |

---

## 08 — ProxyStorageCollision.sol

| # | Vulnerability |
|---|---|
| BUG #1 | `upgrade()`: no storage layout validation; new implementation may use slots 0–2 for different data |
| BUG #2 | `upgradeAndCall()`: delegatecall to `initialize()` may overwrite proxy slots (slot 0 = `implementation`) |
| BUG #3 | `changeAdmin()`: no check if `newAdmin` is a contract with malicious `receive/fallback` |
| BUG #4 | `fallback()`: function selector collision with proxy admin functions (e.g. `upgrade()`) |
| BUG #5 | `fallback()`: no check for admin function selectors being shadowed by implementation |
| BUG #6 | `VulnerableImplementation.initialize()`: writing `owner` to slot 0 overwrites `proxy.implementation` |
| BUG #7 | `VulnerableImplementation.deposit()`: writing `totalDeposits` to slot 1 overwrites `proxy.admin` |
| BUG #8 | `VulnerableImplementation.upgrade()`: function with potentially colliding selector; could shadow proxy's `upgrade()` |
| BUG #9 | `VulnerableImplementation.emergencyWithdraw()`: `owner` (slot 0) is corrupted by proxy; check passes for implementation address |
| BUG #10 | Immutable variables (`MAX_DEPOSIT`, `TRUSTED_ORACLE`, `DEPLOY_TIMESTAMP`) live in bytecode not storage; on upgrade to new implementation with different constructor args, these values silently change without event or migration |

---

## 09 — CrossContractDesync.sol

| # | Vulnerability |
|---|---|
| BUG #1 | `syncBalance()`: reads from vault, stores locally; window between read and store allows vault balance to change |
| BUG #3 | `openPosition()` uses stale `lastKnownVaultBalance` snapshot, not live vault balance |
| BUG #4 | No staleness check on oracle price in `openPosition()` |
| BUG #5 | `openPosition()`: vault withdrawal happens AFTER local state update; if withdrawal fails, local state is already changed |
| BUG #6 | `closePosition()`: cross-contract write without atomicity guarantee |
| BUG #7 | `closePosition()`: PnL calculation assumes linear price change; price feed is manipulable |
| BUG #8 | `closePosition()`: vault deposit may fail, but `localBalance` already cleared; user loses position tracking |
| BUG #9 | `batchSync()`: batch external calls with per-user vault reads; state inconsistent during loop; callback exploitable |
| BUG #10 | `isHealthy()` reads from multiple sources at different time points (live vault vs stale local vs even staler `lastKnown`) |
| BUG #11 | `transfer()`: local balance transfer doesn't notify vault; vault accounting desyncs |
| BUG #12 | `arbitrage()`: exploits desync between vault balance and `lastKnownVaultBalance` for "free" balance via double-spend |
| CHAIN BUG | `syncBalance()` reads price from `flashLoanVictim.getPrice()` which is flash-manipulable; feeds into PrecisionVault (#01) |

---

## 10 — ComboExploitChallenge.sol

| # | Vulnerability |
|---|---|
| VULN #1 | First depositor share inflation: deposit 1 wei, donate 1M tokens, next depositor gets 0 shares |
| VULN #2 | `withdraw()` has no slippage protection (no `minAssets` parameter); user gets less than expected after manipulation |
| VULN #3 | `deposit()`: callback to receiver before `reserveAsset` is updated; receiver can call `getPrice()` and get stale value |
| VULN #4 | `getPrice()` uses `reserveAsset`/`reserveShares` (not actual balance); manipulable during flash loan when reserves are stale |
| VULN #5 | `accumulatedFees` grows forever; no claim/distribute function; ghost value permanently locked |
| VULN #6 | `_updateRewards()`: uses current `balanceOf` not time-weighted; user who got shares this block gets full block reward |
| VULN #7 | `activateEmergency()` + `emergencyWithdraw()` have no cooldown/timelock; guardian can front-run users and drain in same tx |

**Combo chains:** 1+2+4 = Vault drain · 3+6 = Double reward claim · 5+7 = Protocol insolvency

---

## 11 — Create2Metamorphic.sol

| # | Vulnerability |
|---|---|
| BUG (deploy) | No check if address was previously used and destroyed; redeployment at same address possible |
| BUG (registerApproval) | Approval persists in registry even after selfdestruct + redeploy of target contract |
| BUG (destroyDeployed) | Address slot cleared but `isTrusted` and `approvalRegistry` entries are NOT cleared after destruction |
| BUG (checkTrusted) | Returns `true` even for destroyed + redeployed contracts (stale trust) |
| BUG (redeployMalicious) | New contract at same address inherits all token approvals and trust from the old one |

---

## 12 — DirtyHigherBits.sol

| # | Vulnerability |
|---|---|
| BUG (addAdmin) | Stores cleaned address but check callers may supply dirty higher bits, causing mismatch |
| BUG (addToWhitelist) | Different hash produced if input address has dirty upper 96 bits |
| BUG (isWhitelisted) | `keccak256` hashes full 32 bytes from calldata including dirty bits; hash won't match clean-stored version |
| BUG (withdrawWithSig) | Signature covers raw calldata but nonce/replay hash uses cleaned address; dirty bits yield different `sigHash`, enabling replay |
| BUG #5 | `calldataload` reads full 32 bytes including dirty higher bits; same address with different dirty bits → different hash → whitelist bypass |
| BUG #6 | Assembly `eq()` compares full 32 bytes; dirty-padded address fails/passes comparison incorrectly against clean storage |
| BUG #7 | `abi.encodePacked(uint128, uint128)` produces same bytes as `abi.encodePacked(uint256)` → hash collision between different parameter types |
| BUG #8 | Raw calldata including dirty higher bits forwarded through `delegatecall` to target contract; target's assembly reads see dirty data |

---

## 13 — TransientStorageLeak.sol

| # | Vulnerability |
|---|---|
| BUG (isLocked) | Other contracts can read the transient reentrancy guard state via delegatecall |
| BUG (deposit) | Cached balance stored in transient storage persists for entire transaction, leaking across calls |
| BUG (withdrawCached) | Uses cached transient balance that may belong to a different caller within the same transaction |
| BUG (setAuthorizedCaller) | Authorization persists in transient storage across all calls in the same transaction |
| BUG (privilegedAction) | Authorization set by contract A applies to contract B in same transaction (cross-contract transient leak) |
| BUG (flashLoan) | Flash loan active flag in transient storage is visible to all contracts in same transaction |
| BUG (isFlashLoanActive) | Exposes flash loan status to external callers, enabling information leak |
| BUG (callExternal) | `AUTHORIZED_CALLER_SLOT` not cleared after external call; persists for rest of transaction |

---

## 14 — SequencerDownOracle.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Grace period too short (1 hour); stale price still returned during grace period instead of reverting |
| BUG #2 | Stale price is still usable during the grace period after sequencer restarts |
| BUG #3 | Stale price check is weak; `updatedAt` threshold insufficient to reject manipulation |
| BUG (getPriceUnsafe) | Exposes price without any sequencer check or staleness validation; used as fallback |
| BUG (liquidate) | Falls back to unsafe price when `getLatestPrice` reverts, including during "Sequencer is down" |
| BUG (healthFactor) | Uses different price source (safe) than `liquidate` (which falls back to unsafe), creating inconsistency |

---

## 15 — SandwichableView.sol

| # | Vulnerability |
|---|---|
| BUG (getRate) | Used as oracle by external protocols; manipulable via swap in same transaction |
| BUG (getLPPrice) | LP token price is manipulable; classic read-only reentrancy target |
| BUG (getSafeRate) | Returns current (manipulated) rate on same-block queries instead of last known safe rate |
| BUG (getTWAP) | Only uses 2 data points (last + current); trivially manipulable |
| BUG (swap) | Updates `lastRate` AFTER swap; external calls during the function see manipulated rate |
| BUG (flashSwap) | Optimistically transfers reserves, manipulating rate; callback during manipulated state allows sandwich |
| BUG (VictimLending) | Uses manipulable `getLPPrice()` for collateral valuation |

---

## 16 — ZKProofMalleability.sol

| # | Vulnerability |
|---|---|
| BUG #1 | No commitment uniqueness check; same commitment can be added multiple times (double-deposit) |
| BUG #2 | Nullifier computed from public inputs only; attacker can craft different proofs for same nullifier |
| BUG #3 | No field prime validation on public inputs; values > `FIELD_PRIME` wrap around, breaking uniqueness |
| BUG #4 | Uses cached/historic merkle root that could be stale |
| BUG #5 | Nullifier check happens AFTER external value transfer; reentrancy window allows double-spend |
| BUG #6 | `isNullifierUsed` view function exists but is never called inside `withdraw` |
| BUG #7 | No proof that new root is a valid extension of old root; anyone with operator role sets arbitrary root |
| BUG #8 | Historic merkle roots never expire; old roots remain valid forever |
| BUG #9 | `withdrawWithFlashState` uses `FlashLoanVictim.getPrice()` for dynamic withdrawal amount; flash loan can inflate the withdrawn amount |
| BUG #10 | No check if same nullifier appears multiple times within the same batch |
| BUG #11 | `withdrawL2Safe` emergency path when sequencer is down skips ZK proof verification entirely |
| BUG #12 | Mock verifier returns `true` for any proof when `testMode` is enabled |

---

## 17 — L2SequencerExploit.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Message hash doesn't include chain ID; same message can be replayed on different L2s/forks |
| BUG #2 | Challenge period (7 days) can be bypassed when sequencer is down |
| BUG #3 | No verification that `msg.sender` is the bridge; anyone can call with arbitrary "L1 message" |
| BUG #4 | No force-inclusion fallback; if sequencer censors, user messages are stuck |
| BUG #5 | Force inclusion delay (1 hour) < challenge period (7 days); can finalize fraudulent withdrawal before challenge expires |
| BUG #6 | No validation of `txData` format; arbitrary call execution from force-included transaction |
| BUG #7 | No bond/stake required to submit state root; anyone can submit without collateral |
| BUG #8 | Challenge period bypassed entirely when sequencer is reported down |
| BUG #9 | `block.timestamp` on L2 is set by sequencer and can be manipulated to skip challenge period |
| BUG #10 | No reward for successful challengers; no economic incentive to detect fraud |
| BUG #11 | Blob gas price has no validated source; attacker sets high price to DoS batch submissions |
| BUG #12 | Manipulated `blobGasPrice` of 0 makes batch submission free; no minimum cost enforced |
| BUG #13 | Uses cached price from GhostStateOracle on another L2 with no freshness/chain-specific validation |
| BUG #14 | No verification that collateral actually exists on the other L2; user claims phantom collateral |
| BUG #15 | Sequencer can reorder transactions to extract MEV; no public mempool on L2 |
| BUG #16 | ZK proof not re-verified for this L2's chain ID; proof from L2_A replayed on L2_B |
| BUG #17 | Merkle root not verified as belonging to this specific chain |
| BUG #18 | Sequencer atomically executes flash loan + price manipulation; no MEV protection on L2 |
| BUG #19 | Flash loan inflates price → cross-L2 borrow at inflated rate → repay at real price for net profit |

---

## 18 — AccountAbstractionVuln.sol

| # | Vulnerability |
|---|---|
| BUG #1 | No MEV protection; bundler sees `callData` and can front-run the trade inside |
| BUG #2 | Nonce check happens AFTER validation; reentrancy during validation can replay the operation |
| BUG #3 | Bundler controls ordering of operations within batch to extract maximum MEV (sandwich) |
| BUG #4 | Signature malleability (ECDSA s-value) not checked; two valid signatures for same message |
| BUG #5 | `userOpHash` doesn't include `chainId` or `address(this)`; same UserOp valid on mainnet and forks |
| BUG #6 | No per-user limit on gas sponsorship; attacker creates many accounts to drain paymaster |
| BUG #7 | Paymaster deposit deducted before execution; if execution fails, paymaster still pays |
| BUG #8 | Gas refund uses `tx.gasprice` instead of `op.maxFeePerGas`; can underflow or give wrong refund |
| BUG #9 | If paymaster's `postOp` reverts, funds are still deducted with no recovery |
| BUG #10 | Aggregation collision: two different op sets could produce same aggregated BLS signature |
| BUG #11 | Same aggregated signature validates different op sets if hash collision occurs in BLS |
| BUG #12 | Anyone can register as a signature aggregator with no access control |
| BUG #13 | No reentrancy guard during simulation; wallet can call back into EntryPoint |
| BUG #14 | Malicious wallet can call `handleOp`, drain deposits, and modify nonces during simulation callback |
| BUG #15 | Callback via `CallbackReentrancy.safeMint` can reenter the AA contract during execution |
| BUG #16 | Flash loan inside UserOp execution; FlashLoanVictim's callback can manipulate AA state |
| BUG #17 | Uses AuthorityChain's transitive delegation; delegate's delegate can execute for original wallet |
| BUG #18 | Wallet can detect estimation mode (return low gas) vs real execution (use high gas), DoSing the bundler |

---

## 19 — BridgeOracleManipulation.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Finality block assumptions are dangerously low (1 block for Arbitrum/Optimism, 12 for ETH mainnet instead of ~64) |
| BUG #2 | No timelock on guardian additions; attacker adds malicious guardian immediately |
| BUG #3 | No check that remaining guardians stay above `requiredSignatures` threshold; also leaves array gap via `delete` |
| BUG #4 | Uses AuthorityChain's transitive delegation; delegate's delegate can modify guardians |
| BUG #5 | No minimum deposit amount; dust spam possible |
| BUG #6 | Message hash doesn't include timestamp or nonce; identical deposits are indistinguishable |
| BUG #7 | No timeout on confirmations; old unconfirmed deposits remain valid forever |
| BUG #8 | Guardian can re-confirm same deposit if removed and re-added |
| BUG #9 | 2-of-3 oracle compromise gives full fund drain capability (fake deposit confirmation) |
| BUG #10 | No verification that `messageHash` actually matches the supplied `recipient`/`amount`/`sourceChain` parameters |
| BUG #11 | No liquidity check; if chain is drained, message is marked processed and permanently lost |
| BUG #12 | Finality blocks are wrong for L2s; 1 block is insufficient |
| BUG #13 | No way to verify `sourceBlock` is correct; guardians can lie about block number |
| BUG #14 | `processedMessages` is per-chain; after a fork, same messageHash can be executed on both chains |
| BUG #15 | Uses stale cached price from GhostStateOracle for cross-chain conversion |
| BUG #16 | No slippage protection; price can change during bridge delay |
| BUG #17 | Exposes exact liquidity ratio, enabling optimal arbitrage calculation |
| BUG #18 | Uses ZK bridge's merkle root which can be stale or manipulated |
| BUG #19 | Nullifier checked only on this contract, not synced with ZK bridge's own nullifier set |
| BUG #20 | Forwards to L2SequencerExploit which has the message replay bug (no chain ID in hash) |

---

## 20 — RestakingSlashingCascade.sol

| # | Vulnerability |
|---|---|
| BUG #1 | No minimum stake required to register as operator |
| BUG #2 | Can change withdrawal recipient after initiating withdrawal; no timelock or pending-withdrawal check |
| BUG #3 | Same stake can secure multiple AVS; `totalSecured` counts the same stake multiple times |
| BUG #4 | Anyone can create an AVS with any slashing rate; no verification of AVS contract legitimacy |
| BUG #5 | Slashing cascade: multiple slashes trigger systemic cascade affecting all registered AVS |
| BUG #6 | Other AVS not notified of reduced stake after a slash; they still assume original stake ("fake security") |
| BUG #7 | Cascade propagates to delegators; delegators lose stake, and if also operators, cascade continues |
| BUG #8 | No cap on cascade depth; can recursively drain the entire restaking system |
| BUG #9 | Operator can intentionally self-slash to trigger cascade (griefing attack); no cooldown |
| BUG #10 | Delegated stake added to `delegatedStake` but NOT to `totalStake`; AVS security accounting is incorrect |
| BUG #11 | Can undelegate during slash processing; front-run a slash to withdraw before it executes |
| BUG #12 | Can change recipient after slash but before withdrawal completion |
| BUG #13 | Withdrawal uses original pre-slash amount; slashing during delay period doesn't reduce the withdrawal |
| BUG #14 | Circular restaking: LST → Restaking → LST creates infinite leverage loop |
| BUG #15 | Flash loan temporarily inflates stake to register for AVS; repay flash loan → actual stake lower than registered |
| BUG #16 | PrecisionVault share inflation attack affects restaking valuation; static 1:1 rate assumption is wrong |
| BUG #17 | Uses stale cached price from GhostStateOracle for restaking calculations |
| BUG #18 | No verification that stake exists on the other chain; uses bridge liquidity as fake "proof" |
| BUG #19 | AVS security metric is inflated due to double/triple counting of shared operator stake |
| BUG #20 | No cooldown on register/unregister cycle; operator farms AVS airdrop points with no penalty |

---

## 21 — TokenPoisoning.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Zero-value transfers create fake tx history entries (address poisoning); no minimum transfer amount |
| BUG #1b | `sendToLastRecipient` trusts `lastRecipient` from potentially poisoned history |
| BUG #2 | Approval race condition: changing approval from N to M allows front-runner to spend N+M total |
| BUG #3 | Fee-on-transfer tokens: contract credits sent amount, not received amount → insolvency |
| BUG #3b | Withdrawal sends full credited amount even though actual balance is less |
| BUG #4 | Rebasing token balance desync: stores absolute amounts that go stale on rebase |
| BUG #4b | Gap between tracked deposits and actual rebased balance is exploitable |
| BUG #4c | Anyone can claim rebase surplus (no access control on `claimRebaseSurplus`) |
| BUG #5 | Token callback hooks (ERC-777 `tokensReceived`) enable reentrancy: external call before state update |
| BUG #5b | `tokensReceived` callback executes during deposit when state is not yet updated |
| BUG #6 | Infinite approval (`type(uint256).max`) with no expiry, cap, or revocation; permanent drain risk |
| BUG #6b | Permit + transferFrom = gasless drain: leaked/phished signature allows instant token theft |
| BUG #7 | Governance flash loan: voting power updated immediately with no snapshot/timelock |
| BUG #7b | Flash-loaned voting power accepted (no snapshot at proposal creation) |
| BUG #7c | Proposal can be executed in same tx as vote if quorum met |
| BUG #7d | Anyone can create proposals with no proposer threshold |
| BUG #8 | Non-standard ERC-20 return values not handled (USDT returns void → `abi.decode` fails) |
| BUG #9 | Double-spend via permit race: front-runner replays permit signature to drain 2× |
| BUG #10 | Share-based vault donation attack: first depositor inflates share price, second depositor gets 0 shares |
| No-access-control BUG | `setExternalContracts` has no access control |
| Governance BUG | `executeProposal` makes arbitrary low-level call from governance |

---

## 22 — PectraExploits.sol

| # | Vulnerability |
|---|---|
| BUG #1 | EIP-7702 delegation hijack: no validation that delegatee contract code is safe |
| BUG #2 | Cross-chain delegation replay: chain ID missing from authorization hash |
| BUG #3 | Delegation revocation failure: revocation doesn't propagate to cached state in other contracts |
| BUG #3b | Transient storage retains delegation during same tx even after revoke |
| BUG #3c | TOCTOU on delegation: delegation can be revoked between check and delegatecall execution |
| BUG #4 | EOF code validation bypass: no check that contract is actually EOF-formatted (0xEF0001) |
| BUG #5 | Assumes EOF contracts are safe (no SELFDESTRUCT) but registration doesn't verify EOF format |
| BUG #5b | No return data size limit on EOF call → returndata bomb possible |
| BUG #6 | Blob gas price oracle manipulation: anyone can call `updateBlobBaseFee` → exponential fee spike → L2 DoS |
| BUG #6b | `getBlobCost` uses the manipulable blob fee |
| BUG #7 | Validator registration uses old `LEGACY_MAX_EFFECTIVE` (32 ETH) constant; post-Pectra should accept up to 2048 ETH |
| BUG #8 | Validator consolidation: no check that combined balance ≤ `PECTRA_MAX_EFFECTIVE` (2048 ETH) |
| BUG #8b | `totalStaked` not reduced when source validator is consolidated → phantom stake inflation |
| BUG #9 | Deposit queue has no rate limiting; flooding with minimum deposits delays legitimate validators |
| BUG #9b | No duplicate pubkey check in deposit queue |
| BUG #10 | Execution-layer triggered exits (EIP-7002) with no minimum active time / cooldown |
| BUG #10b | Exit during pending consolidation → stake counted twice |
| BUG #10c | Exit returns `effectiveBalance` instead of `consolidatedBalance`; stale after consolidation |
| BUG #11 | Delegation chain amplification: transitive delegation × EIP-7702 code delegation creates N attack surfaces |
| BUG #12 | Delegation + permit chain attack: EIP-7702 + EIP-2612 = gasless drain via single phished signature |
| No-access-control BUG | `setExternalContracts` has no access control |
| Signature BUG | `_recoverSigner` has no s-value malleability check |

---

## 23 — IntentMEV.sol

| # | Vulnerability |
|---|---|
| BUG #1 | Intent cross-chain replay: `intentHash` missing `block.chainid` and `address(this)` |
| BUG #2 | Stale intent exploitation: deadline checks only `block.timestamp`, not price freshness |
| BUG #3 | Solver collusion: no mechanism to prevent cooperating solvers from suppressing competitive bids |
| BUG #3b | Bid amounts visible on-chain → last-mover advantage |
| BUG #3c | Winning solver keeps ALL surplus between bid and actual execution cost |
| BUG #4 | Partial fill manipulation: 10% minimum fill lets solver drip-fill at worst price each time |
| BUG #4b | No check that cumulative partial fills don't exceed 100% of intent |
| BUG #5 | Cross-domain MEV: no verification that cross-chain fill actually happened; uses flash-manipulable local oracle |
| BUG #6 | Shared sequencing front-running: sequencer sees all intents before inclusion → undetectable sandwich |
| BUG #6b | No commit-reveal scheme; sequencer has perfect information advantage |
| BUG #7 | Phantom function call: low-level call to address with no code returns `success=true` |
| BUG #7b | No validation of returndata from solver settlement |
| BUG #8 | Returndata bomb: malicious solver returns massive data → all gas consumed |
| BUG #9 | Unbounded loop DoS: `getAllPendingIntents` returns entire unbounded array → exceeds block gas limit |
| BUG #9b | `cleanupExpiredIntents` iterates O(n) over ever-growing array; expired entries never removed |
| BUG #10 | Order-dependent state: batch fill uses live oracle price that changes between iterations |
| BUG #11 | No solver registration check in `fillIntent`; anyone can fill |
| BUG #11b | Minimum solver stake (1 ETH) too low for intents worth millions |
| BUG #12 | Intent front-running / cancellation race: solver sees cancel in mempool, fills before cancel |
| BUG #13 | Back-running profit extraction: on-chain intent reveals swap details |
| BUG #14 | JIT liquidity attack: solver adds concentrated liquidity at user's price, earns risk-free fees |
| BUG #15 | Time-bandit reorg attack: `parentBlockHash` check insufficient on reorgs |
| No-access-control BUG | `setExternalContracts` has no access control |

---

## 24 — RWAOracleDesync.sol

| # | Vulnerability |
|---|---|
| VULN #1 | NAV oracle staleness: off-chain NAV updated daily but used continuously with no freshness check |
| VULN #2 | Compliance oracle bypass: KYC/AML status cached with 30-day window |
| VULN #3 | Redemption race condition: NAV locked at request time; if real NAV drops, redeemer profits |
| VULN #4 | Treasury proof-of-reserves staleness: 7-day threshold too long; `porStalenessThreshold` can be set to `type(uint256).max` |
| VULN #5 | Collateral proof fraud: `updateNav` proof parameter completely ignored |
| VULN #6 | Multi-oracle desync: no median/TWAP; simple average of desynced oracles |
| VULN #7 | NAV sandwich: front-run NAV update with large mint at stale price, back-run with redeem |
| VULN #8 | Dividend flash loan: `claimDividend` checks balance at call time; `dividendDebt` not subtracted → double-claim |
| VULN #9 | Compliance front-run: pending KYC revocation visible in mempool |
| VULN #10 | Off-chain settlement gap: on-chain delay 1 hour but real settlement T+2; `redemptionDelay` can be 0 |
| VULN #11 | Time-zone arbitrage: NAV priced at NYC close (hardcoded UTC offset, wrong during DST) |
| VULN #12 | Regulatory jurisdiction hop: compliance checked only on source chain; bridged tokens escape compliance |
| Admin BUG | `setNavOracle` and `setComplianceOracle` have no timelock |
| Redemption BUG | No check that redeemer still holds shares at fulfillment |

---

## 25 — TokenBoundAccounts.sol

| # | Vulnerability |
|---|---|
| VULN #1 | Recursive ownership loop: NFT-A → TBA-A → NFT-B → TBA-B → NFT-A creates infinite loop in `owner()` |
| VULN #2 | Trapped assets: if parent NFT is burned, all ETH/ERC20/NFTs inside TBA are permanently inaccessible |
| VULN #3 | Transfer reentrancy: `safeTransferFrom` triggers `onERC721Received` callback with no reentrancy guard |
| VULN #4 | Registry front-run: anyone can create TBA for any NFT (no ownership check); attacker uses malicious implementation |
| VULN #5 | Cross-chain TBA desync: `syncToL2` sends arbitrary `syncData` with no verification or nonce |
| VULN #6 | Ownership confusion: `owner()` returns wrong value during NFT transfer hooks |
| VULN #7 | Execution delegation bypass: no target validation in `executeCall`/`executeBatch` |
| VULN #8 | Nested TBA gas bomb: deeply nested TBAs exhaust gas on `owner()` recursion |
| VULN #9 | NFT approval drain: delegates get FULL unlimited execution rights with no scoping or expiry |
| VULN #10 | TBA storage collision: different implementations for same NFT cause storage clash |

---

## 26 — PreconfBasedRollup.sol

| # | Vulnerability |
|---|---|
| VULN #1 | Preconf promise violation: no enforcement; fulfillment is self-reported with no SPV proof |
| VULN #2 | Proposer MEV extraction: L1 proposer reorders preconfirmed txs for profit |
| VULN #3 | Double-spend window: spend on L2 via preconf, L1 reorg invalidates preconf but L2 state persists |
| VULN #4 | Preconf censorship: proposer selectively excludes valid preconfirmed txs |
| VULN #5 | Preconf timing exploit: no commitment deadline; proposer waits for price movement |
| VULN #6 | DA withholding: blob commitment accepted without proof of data posting; challenge period too short (1 hour) |
| VULN #7 | Blob commitment mismatch: if DA layer is down, challenge always fails |
| VULN #8 | DA offline fallback: manual flag; on error defaults to `daLayerOnline = true` |
| VULN #9 | Cross-L2 partial execution: no rollback; "rollback" is inverse transactions (not atomic) |
| VULN #10 | Cross-L2 front-run: each cross-chain message visible in mempool |
| VULN #11 | Shared sequencer unbundling: no atomicity guarantee for bundles |
| VULN #12 | Proposer bond drain: 10% slash per violation (profitable if MEV > 10% of bond) |
| Reputation BUG | Reputation score easily gamed and not used in preconf acceptance |
| Access-control BUG | `setChainBridge` has no access control |

---

## 27 — AIFHESocialRecovery.sol

**AI Oracle:**

| # | Vulnerability |
|---|---|
| VULN #1 | AI data poisoning: attacker registers poisoned data source; 50% deviation allowed |
| VULN #2 | Prompt injection via on-chain data: token names/symbols confuse AI; `modelHash` not verified |
| VULN #3 | Chainlink Functions manipulation: user-provided JS code can return any value |
| VULN #4 | Confidence score bypass: 30% minimum threshold (AI 70% unsure); no staleness check |

**FHE DeFi:**

| # | Vulnerability |
|---|---|
| VULN #5 | FHE invariant bypass: plain `totalDeposited` leaks info alongside encrypted balances |
| VULN #6 | Decryption timing leak: larger ciphertexts take longer → timing side-channel |
| VULN #7 | Encrypted overflow: `addEncrypted`/`subEncrypted` may overflow in ciphertext space |
| VULN #8 | FHE gas side-channel: gas consumption reveals encrypted balance ranges |

**Social Recovery:**

| # | Vulnerability |
|---|---|
| VULN #9 | Guardian threshold attack: threshold can be set to 1; 1 compromised guardian = instant theft |
| VULN #10 | Recovery timelock bypass: if guardians exceed 2× threshold weight, timelock skipped |
| VULN #11 | Guardian collusion: initiator auto-approves; session keys survive ownership transfer |
| VULN #12 | Social engineering: `guardianCooldown` is 0; `relationship` field stored on-chain |
| Session key BUG | No maximum duration; no spending limit; not revoked on ownership transfer |
| Guardian removal BUG | Owner can remove all guardians to prevent recovery |
| Daily limit BUG | Easily bypassed via token approvals (only checks ETH value) |
| Cross-section VULN | AI price manipulation → FHE deposit at wrong valuation → guardian recovery steals encrypted funds |

---

## 28 — AdvancedReentrancy.sol

| # | Vulnerability |
|---|---|
| RENT-ADV-01 | Delegatecall vault reentrancy: `upgradeAndCall` delegates to user-controlled implementation with no auth |
| RENT-ADV-02 | Pull/push pattern mixed reentrancy: `distributeRewards` sends ETH mid-loop, recipient can re-enter |
| RENT-ADV-03 | Factory/clone reentrancy: CREATE2 deploys and calls constructor, callback before `isClone[addr]` set |
| RENT-ADV-04 | NFT lazy mint reentrancy: `onERC721Received` callback before `totalMinted++`, bypasses `maxSupply` |

---

## 29 — ArithmeticAccessDoS.sol

| # | Vulnerability |
|---|---|
| ARITH-ADV-01 | Vesting release overflow: `totalAmount * elapsed` can overflow before division |
| ARITH-ADV-02 | Timelock reward overflow: `rewardRate * lockDuration` unbounded multiplication |
| ARITH-ADV-03 | Staking bonus multiplier overflow: uncapped `bonusMultiplier` |
| ARITH-ADV-04 | Batch withdraw underflow: balance checked once but decremented in loop |
| ACCESS-ADV-01 | Role hierarchy bypass via proxy context: storage layout mismatch causes wrong slot access |
| ACCESS-ADV-02 | Role enumeration not updated on revoke: stale data in `_roleMembers` |
| ACCESS-ADV-03 | Role-dependent reward bypass: eligibility persists after role revocation |
| DOS-ADV-01 | Batch payout DoS: single recipient revert blocks all payees |
| DOS-ADV-02 | Oracle outage DoS: offline oracle blocks all deposits |
| DOS-ADV-03 | ERC1155 batch hooks gas exhaustion: unbounded array causes out-of-gas |
| DOS-ADV-04 | NFT marketplace settlement DoS: reverting royalty recipient blocks entire sale |

---

## 30 — OracleRandomness.sol

| # | Vulnerability |
|---|---|
| ORACLE-ADV-01 | Oracle feed spoofing cross-chain: L2 oracle accepts relayer prices without L1 Merkle proof |
| ORACLE-ADV-02 | Collateral misvaluation: flashloan pumps spot-oracle price to overborrow |
| RAND-01 | On-chain randomness from `block.timestamp` and `blockhash` (public, miner-influenceable) |
| RAND-02 | VRF seed reuse: same seed → same requestId hash → pre-computation |
| RAND-03 | `block.prevrandao` controllable by validator who can withhold blocks |
| RAND-ADV-01 | VRF callback manipulation: `fulfillRandomWords` doesn't verify `msg.sender` |
| RAND-ADV-02 | Lottery result pre-computation: all inputs public on-chain |
| RAND-ADV-03 | Bet and resolve in same tx; attacker wraps in try/catch to revert on loss |
| RAND-ADV-04 | Commit-reveal timeout: no reveal timeout, player refuses to reveal if unfavorable |
| RAND-ADV-05 | Prediction market oracle gaming: manipulation cost < bet profit |
| RAND-ADV-06 | House edge changeable after bets placed, no cap or timelock |
| RAND-ADV-07 | On-chain poker: cards stored in public mapping |
| RAND-ADV-08 | Dice roll manipulation: `block.prevrandao` known to validator |
| RAND-ADV-09 | Slot machine seed: stored in public storage and emitted in events |

---

## 31 — ProxyUpgradeAdvanced.sol

| # | Vulnerability |
|---|---|
| PROXY-ADV-01 | Beacon `upgradeTo` has no access control; anyone can change implementation |
| PROXY-ADV-02 | Proxy fallback delegates all calls with no selector filtering |
| PROXY-ADV-03 | No version tracking; admin can rollback to any previous buggy implementation |
| PROXY-ADV-04 | Implementation can overwrite guardian storage slot via delegatecall |
| PROXY-ADV-05 | Diamond multi-facet storage misalignment at slot 0 |

---

## 32 — TokenAdvanced.sol

| # | Vulnerability |
|---|---|
| TOKEN-ADV-01 | `type(uint256).max` approval never decreases; approved contract can drain at any time |
| TOKEN-ADV-02 | Reflection fee redistributed to excluded addresses; rate calculation wrong |
| TOKEN-ADV-03 | Anti-whale bypass: cooldown/max-tx limits bypassed via multiple wallets |
| TOKEN-ADV-04 | ERC721 `setTokenURI` allows owner to change metadata after sale |
| TOKEN-ADV-05 | ERC20 approve front-running: direct overwrite enables spend old + new allowance |

---

## 33 — DeFiVaultAdvanced.sol

| # | Vulnerability |
|---|---|
| DEFI-ADV-01 | Flashloan reward manipulation: flashloan → stake → trigger reward → unstake |
| DEFI-ADV-02 | LP share dilution: direct donation inflates share price, next depositor gets 0 shares |
| DEFI-ADV-03 | Pool depletion: many small swaps accumulate rounding error favoring trader |
| DEFI-ADV-04 | Yield farming reward overflow: `rewardRate * elapsed` overflows for large durations |
| DEFI-ADV-05 | Admin can set `unlockTime` to the past; immediate withdrawal of locked funds |
| DEFI-ADV-06 | Multi-vault cross-call reentrancy during withdrawal |
| DEFI-ADV-07 | Fee misallocation: distributed based on current shares, not time-weighted |
| DEFI-ADV-08 | Unchecked reward multiplier: no cap → infinite reward inflation |

---

## 34 — GovernanceExploits.sol

| # | Vulnerability |
|---|---|
| GOV-ADV-01 | Proposal spam: no minimum stake or threshold |
| GOV-ADV-02 | Governance bribery: no prevention; votes publicly visible |
| GOV-ADV-03 | Delegate vote miscount: non-atomic checkpoint → reentrancy double-count |
| GOV-ADV-04 | Multi-chain governance mismatch: chain A decision executed on chain B without state verification |
| GOV-ADV-05 | Governance replay: proposal hash doesn't include `chainId` |
| GOV-ADV-06 | Multi-sig bypass: threshold not updated when signers change |
| GOV-ADV-07 | Quorum reset: burning tokens lowers `totalSupply`, quorum easier to reach |
| GOV-ADV-08 | Proposer cancels after votes cast, wasting voters' gas |

---

## 35 — BridgeCrossChainAdvanced.sol

| # | Vulnerability |
|---|---|
| BRIDGE-ADV-01 | L2 minted amount can exceed L1 locked amount with no cross-chain verification |
| BRIDGE-ADV-02 | Validators added/removed by single orchestrator with no timelock |
| BRIDGE-ADV-03 | ZK-SNARK verification bypass: accepts any non-zero proof, missing pairing check |
| BRIDGE-ADV-04 | ZK-STARK verification bypass: only checks proof length, missing FRI verification |
| BRIDGE-ADV-05 | Sidechain oracle lag: price hours behind mainchain, creating arbitrage |
| BRIDGE-ADV-06 | Cross-rollup state claim without Merkle proof |
| BRIDGE-ADV-07 | L2→L1 withdrawal decimal mismatch (6 vs 18) and fee double-deduction |
| BRIDGE-ADV-08 | Cross-chain reward duplication: claimed flag is per-chain |
| BRIDGE-ADV-09 | Bridge fee overflow: `fee * amount` can overflow |
| BRIDGE-ADV-10 | Validator bribery: cost far below bridge TVL |
| BRIDGE-ADV-11 | Cross-chain mint replay: nonce not tracked |
| BRIDGE-ADV-12 | Centralized orchestrator can reorder, censor, or fabricate messages |

---

## 36 — AssemblyLowLevel.sol

| # | Vulnerability |
|---|---|
| ASM-ADV-01 | Unsafe memcpy/memclear: memory copy without bounds checking overwrites free memory pointer |
| ASM-ADV-02 | Wrong `div` operand order, unused stack value, `returndatasize()` without success check |
| ASM-ADV-03 | Delegatecall: `calldatasize()` used instead of `mload(data)` for input length |
| ASM-ADV-04 | Storage collision via assembly: dynamically computed slots collide with Solidity's layout |
| ASM-ADV-05 | Recursive `CALL` in assembly forwards all gas with no depth limit |

---

## 37 — NFTMarketplaceExploits.sol

| # | Vulnerability |
|---|---|
| NFT-ADV-01 | Lazy mint front-running: tokenId and price visible in mempool |
| NFT-ADV-02 | URI injection: no sanitization, allows javascript/data/phishing URLs |
| NFT-ADV-03 | Delist race condition with pending `buy()` tx |
| NFT-ADV-04 | Fee + royalty can exceed price: `royaltyBps + platformFee > 10000` → seller underflow |
| NFT-ADV-05 | Batch transfer reentrancy: ERC1155 callback allows re-entry |
| NFT-ADV-06 | Fractionalization buyout price manipulable via small trades |
| NFT-ADV-07 | Royalty bypass: direct transfer skips ERC2981 enforcement |
| NFT-ADV-08 | Dutch auction last-second manipulation |
| NFT-ADV-09 | ERC1155 supply not updated on mint → underflow on burn |
| NFT-ADV-10 | Staking reward drain: unstake→restake resets timer, keeps rewards |
| NFT-ADV-11 | Soulbound token bypass: no check in `approve` |
| NFT-ADV-12 | Generative art seed from on-chain data (miner-manipulable) |
| NFT-ADV-13 | Permit replay: nonce not incremented, no chainId |
| NFT-ADV-14 | Bundled sale exploit: bundle price doesn't reflect individual values |
| NFT-ADV-15 | Reveal seed predictable: uses public `blockhash` |

---

## 38 — VestingTimelockExploits.sol

| # | Vulnerability |
|---|---|
| VEST-01 | Cliff period bypass via validator timestamp manipulation (±15 sec) |
| VEST-02 | Admin can modify vesting schedule after vesting started |
| VEST-03 | Integer division rounding loss over small periods |
| VEST-04 | Emergency withdraw takes ALL tokens including vested-but-unclaimed |
| VEST-05 | Shared vesting pool: one beneficiary's claim depletes pool for others |
| VEST-06 | Revocation takes ALL remaining tokens, not just unvested portion |
| VEST-07 | Accumulated rounding error over multiple small claims |
| VEST-08 | Admin can swap vesting token address to a worthless token |

---

## 39 — RewardIncentiveExploits.sol

| # | Vulnerability |
|---|---|
| REWARD-01 | `rewardPerToken` precision loss when `totalStaked` is very large |
| REWARD-02 | Retroactive farming: stake right before distribution captures full reward |
| REWARD-03 | Compound without cooldown: called every block for exponential growth |
| REWARD-04 | Airdrop double claim: claimed flag set after ETH transfer (reentrancy) |
| REWARD-05 | Self-referral: no check that `ref != msg.sender` |
| REWARD-06 | Whale dilution: large deposit before distribution dilutes all stakers |
| REWARD-07 | Boosted reward overflow: `baseReward * boost * duration` overflows |
| REWARD-08 | No cap on reward token minting: infinite inflation |
| REWARD-09 | Multi-pool claim exceeds total: same reward claimable from multiple pools |
| REWARD-10 | Wrong epoch emission rate: uses previous epoch's higher rate |
| REWARD-11 | Loyalty points reentrancy: ETH sent before points deduction |
| REWARD-12 | Dividend snapshot gaming: buy before snapshot, claim, sell |
| REWARD-13 | Gauge voting bribe: votes purchasable off-chain |
| REWARD-14 | veToken lock: early unlock via admin override |
| REWARD-15 | Rebasing token reward miscalc: double-counting |
| REWARD-16 | Reward claim reentrancy: ETH sent before `rewards = 0` |
| REWARD-17 | Merkle leaf hash collision: `abi.encodePacked` with dynamic types |
| REWARD-18 | Early withdrawal penalty bypass: transfer stake to another address |

---

## 40 — EdgeCaseExploits.sol

| # | Vulnerability |
|---|---|
| EDGE-01 | EIP-2930 access list changes SLOAD gas cost, breaking hardcoded gas checks |
| EDGE-02 | CREATE2 redeploy: after selfdestruct, different contract at same address |
| EDGE-03 | Transient storage leak: TSTORE persists entire tx, readable by other contracts |
| EDGE-04 | EIP-4337 validation phase accesses forbidden external storage |
| EDGE-05 | Permit2 infinite allowance (`type(uint256).max`) is permanent |
| EDGE-06 | Ether lockup: accepts ETH but has no withdraw function |
| EDGE-07 | Selfdestruct callable by anyone, no access control |
| EDGE-08 | Gas token abuse: mints empty contracts for SELFDESTRUCT gas refund |
| EDGE-09 | ECDSA signature malleability: no `s < secp256k1n/2` check |
| EDGE-10 | Dirty high bits: upper 96 bits cause assembly comparison mismatch |
| EDGE-11 | Payable multicall reuses `msg.value`: pay once, do N operations |
| EDGE-12 | Unchecked return value: `success` variable never checked |
| EDGE-13 | Block gas limit DoS: unbounded `users` array loop |
| EDGE-14 | Allowance not decremented on `transferFrom`: infinite transfers |
| EDGE-15 | Enum out of bounds: casting uint to enum with unexpected values |
| EDGE-16 | Phantom function: non-existent selector falls through to delegatecall fallback |
| EDGE-17 | Return bomb: target returns massive data, exhausting caller gas |

---

## 41 — LiquidationInitExploits.sol

| # | Vulnerability |
|---|---|
| LIQ-ADV-01 | Flash loan manipulation before liquidation: crash oracle price, liquidate healthy positions |
| LIQ-ADV-02 | Partial liquidation rounding: `debt / 2` rounds down, leaving dust positions |
| LIQ-ADV-03 | Cascading liquidations: liquidating one user crashes price, triggering cascade |
| LIQ-ADV-04 | Self-liquidation for profit: liquidator == borrower, captures own bonus |
| LIQ-ADV-05 | Stale oracle allows unfair liquidation: price may have recovered |
| INIT-ADV-01 | Uninitialized proxy: storage hijacked before init call |
| INIT-ADV-02 | Re-initialization: no "already initialized" check |
| INIT-ADV-03 | Constructor sets state on implementation, not proxy |
| INIT-ADV-04 | `initializeV2` has no initializer guard or version check |
| INIT-ADV-05 | Initialization is front-runnable: not called in same tx as deployment |

---

## 42 — MEVAdvancedExploits.sol

| # | Vulnerability |
|---|---|
| MEV-ADV-01 | Sandwich attack: tx visible in mempool |
| MEV-ADV-02 | JIT liquidity: add/remove in same block to capture fees |
| MEV-ADV-03 | Backrun arbitrage: oracle lag after large swap |
| MEV-ADV-04 | Oracle update front-running visible in mempool |
| MEV-ADV-05 | Time-bandit attack: reward incentivizes block reorg |
| MEV-ADV-06 | NFT snipe bot: bots snipe all supply at mint |
| MEV-ADV-07 | Liquidation MEV race: priority gas auction (PGA) |
| MEV-ADV-08 | Slippage hardcoded to 0: maximum sandwich extraction |
| MEV-ADV-09 | Cross-domain MEV: L1/L2 price differences create arbitrage |
| MEV-ADV-10 | Gas auction griefing: competing bots waste block space |

---

## 43 — StorageTimingLogic.sol

| # | Vulnerability |
|---|---|
| STOR-ADV-01 | Storage slot collision via inheritance: slot shift on parent insertion |
| STOR-ADV-02 | Struct packing overflow: `uint128` overflow into adjacent timestamp field |
| STOR-ADV-03 | Dynamic array storage overlaps mapping at `keccak256(slot) + index` |
| STOR-ADV-04 | Mapping key collision: `abi.encodePacked("ab","c") == abi.encodePacked("a","bc")` |
| STOR-ADV-05 | ERC-7201 namespace collision: identical namespace hash |
| XCON-ADV-01 | Cross-contract view dependency: result changes mid-tx |
| XCON-ADV-02 | Shared state mutation: two contracts race on same state |
| XCON-ADV-03 | Callback state desync: re-entrant callback modifies intermediate state |
| XCON-ADV-04 | Library delegatecall corrupts caller storage (overwrites owner) |
| XCON-ADV-05 | Multi-contract invariant break between sync calls |
| TIME-ADV-01 | Block timestamp manipulation (±15 sec): 60-second lock bypassable |
| TIME-ADV-02 | `block.number` as time proxy: varies across chains |
| TIME-ADV-03 | Deadline bypass: off-by-one allows execution AT deadline |
| TIME-ADV-04 | Epoch transition race: claim at boundary gets wrong/both epoch rewards |
| TIME-ADV-05 | Cooldown reset: any action resets `lastAction` |
| LOGIC-ADV-01 | Wrong comparison: `>` instead of `>=` |
| LOGIC-ADV-02 | Off-by-one in loop: `<= length` instead of `<` |
| LOGIC-ADV-03 | Inverted ternary: high spenders get no discount |
| LOGIC-ADV-04 | Missing break: all conditions evaluated, last wins |
| LOGIC-ADV-05 | Unsigned negation: `0 - value` underflows |

---

## 44 — ComboMultiVector.sol

| # | Vulnerability |
|---|---|
| COMBO-01 | Flash loan + governance takeover in same tx |
| COMBO-02 | Reentrancy + oracle manipulation: external call before state update |
| COMBO-03 | Upgrade + selfdestruct: admin upgrades to self-destructing implementation |
| COMBO-04 | MEV + flash loan sandwich: no slippage protection |
| COMBO-05 | Cross-chain flash loan: borrow on chain A, exploit on chain B |
| COMBO-06 | Proxy + delegatecall function selector collision |
| COMBO-07 | Oracle + AMM feedback loop: circular price dependency |
| COMBO-08 | ERC-777 callback + reentrancy via `tokensReceived` |
| COMBO-09 | Front-run initialization: attacker sets quorum to 1 |
| COMBO-10 | Liquidation callback reentrancy before state update |
| COMBO-11 | Fee-on-transfer + vault accounting mismatch |
| COMBO-12 | Bridge message replay: no destination chainId |
| COMBO-13 | EIP-2612 permit phishing: sign for dApp A, used by dApp B |
| COMBO-14 | Assembly `sstore` in proxy overwrites implementation address |
| COMBO-15 | Vault share inflation via donation |
| COMBO-16 | CREATE2 + metamorphic: redeploy different code at same address |
| COMBO-17 | Multi-token reentrancy: ERC-721 + ERC-1155 callback chains |

---

## 45 — MegaEdgeCases.sol

| # | Vulnerability |
|---|---|
| MEGA-01 | EIP-3074 AUTH abuse: no invoker whitelist validation |
| MEGA-02 | ERC4626 share price manipulation: deposit 1 wei, donate, next depositor gets 0 shares |
| MEGA-03 | `abi.encodePacked` collision with dynamic types |
| MEGA-04 | Unprotected ETH transfer: no access control |
| MEGA-05 | USDT-like tokens don't return bool → `abi.decode` fails |
| MEGA-06 | `transfer()` hardcoded 2300 gas fails for complex fallbacks |
| MEGA-07 | Token decimals mismatch: hardcoded 18, wrong for USDC (6) |
| MEGA-08 | `setOwner(address(0))` locks contract forever |
| MEGA-09 | Unprotected proxy admin: anyone can change implementation |
| MEGA-10 | Constructor not payable but references deploy-time value |
| MEGA-11 | Immutable `deployFee` cannot be updated if incorrect |
| MEGA-12 | Strict `balance == totalDeposits` broken by force-fed ETH |
| MEGA-13 | ERC777 `send()` reentrancy via `tokensReceived` hook |
| MEGA-14 | ABI decode type confusion: `(uint256, address)` decoded as `(address, uint256)` |
| MEGA-15 | Modifier order: `onlyOwner` before `nonReentrant` → guard never engaged |
| MEGA-16 | `uint256` → `uint128` silent truncation |
| MEGA-17 | Solidity optimizer bug (0.8.13–0.8.17): may skip memory cleanup |
| MEGA-18 | Unbounded dynamic array exceeds block gas limit |
| MEGA-19 | Centralized pause: single owner, no timelock |
| MEGA-20 | Missing slippage protection: no `minAmountOut` |
| MEGA-21 | Withdrawal queue: anyone can process, skipping entries |
| MEGA-22 | Price impact unchecked: single trade moves price 50%+ |
| MEGA-23 | Emergency admin backdoor: no timelock or multisig |
| MEGA-24 | Stale price after depeg: hardcoded 1 USD for USDC |
| MEGA-25 | Rebasing token not handled: deposit tracking by amount |
| MEGA-26 | DoS via revert in loop: one recipient blocks all payments |
| MEGA-27 | Missing swap deadline: `block.timestamp` always passes |
| MEGA-28 | Private data on-chain: `secret` readable via `getStorageAt` |
| MEGA-29 | Forced ETH via selfdestruct breaks strict equality |
| MEGA-30 | View functions not protected by `nonReentrant`: return inconsistent state |

---

## 46 — UniswapV4Hooks.sol

| # | Vulnerability |
|---|---|
| HOOK-REENTER-01 | beforeSwap hook re-enters swap function, draining pool reserves |
| HOOK-REENTER-02 | afterSwap hook manipulates state to extract value on next swap |
| HOOK-INJECT-01 | Malicious hook injected via pool initialization with custom hook address |
| HOOK-FEE-01 | Dynamic fee hook overcharges users by returning manipulated fee |
| HOOK-FEE-02 | Fee hook returns different values for same pool depending on caller |
| HOOK-INIT-01 | Pool initialization with malicious sqrtPriceX96 traps first LP |
| HOOK-TICK-01 | Hook manipulates tick during swap callback, displacing liquidity range |
| HOOK-LIQ-01 | beforeAddLiquidity hook front-runs LP deposit to sandwich |
| HOOK-PERM-01 | Hook flags claim more permissions than needed, enables data exfiltration |
| HOOK-FLASH-01 | Flash loan callback within hook re-enters pool manager |
| HOOK-DELTA-01 | Hook modifies balance deltas to steal funds during settlement |
| HOOK-STORAGE-01 | Transient storage in hook leaks across calls within same transaction |
| HOOK-RET-01 | Hook return data misinterpreted, wrong selector accepted as valid |
| HOOK-XPOOL-01 | Cross-pool hook state shared, one pool's hook affects another |
| HOOK-DONATE-01 | donate() called in hook to manipulate LP fee accrual |
| HOOK-CLAIM-01 | Hook claims protocol fees meant for governance |
| HOOK-KEY-01 | PoolKey with hookAddress near selector boundary triggers wrong hook |
| HOOK-NOOP-01 | NoOp hook flag skips liquidity check, allows 0-collateral position |
| HOOK-TSTORE-01 | Transient storage used across hooks not cleared between pools |
| HOOK-SELFDESTRUCT-01 | Hook self-destructs after deployment, pool permanently bricked |

---

## 47 — LiquidStakingDerivatives.sol

| # | Vulnerability |
|---|---|
| LSD-DEPEG-01 | stETH/ETH exchange rate diverges during mass withdrawals |
| LSD-DEPEG-02 | Withdrawal queue delay enables depeg arbitrage |
| LSD-REBASE-01 | Rebasing accounting miscounts shares during negative rebase |
| LSD-REBASE-02 | Positive rebase distributed unevenly between stakers |
| LSD-ORACLE-01 | Oracle reports stale beacon chain balance, deposit mispriced |
| LSD-SLASH-01 | Validator slashing not propagated to derivative token holders |
| LSD-SLASH-02 | Slashing socialized across all holders instead of specific validator |
| LSD-QUEUE-01 | Withdrawal queue can be griefed with many micro-withdrawals |
| LSD-QUEUE-02 | Queue position transferable, creates secondary market that front-runs |
| LSD-MEV-01 | Validator MEV extracted but not shared with derivative holders |
| LSD-DEFI-01 | wstETH used as collateral, but rebase changes effective LTV |
| LSD-GOV-01 | Token governance power retained by staking protocol, not holders |
| LSD-FEE-01 | Node operator fee changed retroactively |
| LSD-SANDWICH-01 | Large stake/unstake operations sandwiched on Curve/Uni |
| LSD-ENTRY-01 | Entry/exit fee manipulation through validator count gaming |
| LSD-MINIPOOLS-01 | Minipool operators can steal delegated stake |
| LSD-BEACON-01 | Beacon chain finality delay creates withdrawal timing attack |
| LSD-DVT-01 | DVT key share compromise enables partial validator control |
| LSD-COMPOUND-01 | Auto-compounding skimmed by operator |
| LSD-EMERGENCY-01 | Emergency withdrawal bypasses queue, drains reserves |

---

## 48 — PerpetualFunding.sol

| # | Vulnerability |
|---|---|
| PERP-FUND-01 | Funding rate manipulated by skewing open interest |
| PERP-FUND-02 | Funding payment calculated on mark price, not index → divergence exploit |
| PERP-MARK-01 | Mark price uses internal TWAP, manipulable via wash trading |
| PERP-MARK-02 | Index price oracle has 15-min TWAP lag, stale during volatility |
| PERP-LIQ-01 | Cascading liquidations in same block push price through multiple positions |
| PERP-LIQ-02 | Liquidation incentive too high, profitable to push positions underwater |
| PERP-LIQ-03 | Partial liquidation leaves dust positions that can't be liquidated |
| PERP-INS-01 | Insurance fund drained by coordinated large-position defaults |
| PERP-INS-02 | Insurance fund yield farming reduces available emergency capital |
| PERP-ADL-01 | Auto-deleverage selects profitable traders unfairly |
| PERP-SIZE-01 | Max position size not enforced per-account when using multiple sub-accounts |
| PERP-MARGIN-01 | Cross-margin lets one position's loss drain all margin |
| PERP-FEE-01 | Maker/taker fee bypass via self-trading |
| PERP-ENTRY-01 | Entry price manipulation via oracle front-running |
| PERP-CLOSE-01 | Close-only mode bypassed through position transfer |
| PERP-INTEREST-01 | Borrow rate calculation skips compounding |
| PERP-REALIZEDPNL-01 | Realized PnL credited before settlement delay |
| PERP-DUST-01 | Dust positions accumulate untouchable bad debt |
| PERP-ORACLE-01 | Sequencer downtime creates stale mark price → unfair liquidations |
| PERP-SETTLE-01 | Settlement contract upgrade changes PnL calculation retroactively |

---

## 49 — StablecoinDepeg.sol

| # | Vulnerability |
|---|---|
| STABLE-PSM-01 | Peg stability module drained by arbitraging depegged collateral |
| STABLE-PSM-02 | PSM fee set to 0 allows free arb at protocol expense |
| STABLE-DEPEG-01 | Oracle reports $1.00 while market price is $0.90, bad loans issued |
| STABLE-BANKRUN-01 | Mass redemption triggers bank-run, insufficient reserves |
| STABLE-CURVE-01 | Curve pool imbalance amplified by A parameter during depeg |
| STABLE-CR-01 | Collateral ratio drops below 100%, algorithmic mint unable to restore |
| STABLE-ALGO-01 | Algorithmic burn/mint mechanism enters death spiral |
| STABLE-GOV-01 | Governance vote to lower collateral ratio during stress |
| STABLE-LIQTHRESH-01 | Liquidation threshold too close to depeg price, cascading defaults |
| STABLE-BADDEBT-01 | Bad debt accumulates when collateral falls faster than liquidation |
| STABLE-KEEPERUSC-01 | Keeper bot network fails during congestion, no liquidations |
| STABLE-FLASHMINT-01 | Flash mint used to manipulate governance votes then repay |
| STABLE-MULTICOL-01 | Multi-collateral basket: one asset depegs, taints entire basket |
| STABLE-RATE-01 | Stability fee rate change applied retroactively to existing vaults |
| STABLE-SHUTDOWN-01 | Emergency shutdown gives unfair advantage to last redeemers |
| STABLE-RESERVE-01 | Reserve proof-of-reserves is off-chain, not verifiable on-chain |
| STABLE-REBASE-01 | Rebasing stablecoin breaks DeFi integrations expecting fixed balance |
| STABLE-XCHAIN-01 | Cross-chain stablecoin supply desync between L1 and L2 |

---

## 50 — ConcentratedLiquidityMEV.sol

| # | Vulnerability |
|---|---|
| CLMEV-JIT-01 | Just-in-time liquidity added before large swap, removed after fees collected |
| CLMEV-JIT-02 | JIT LP front-runs rebalance transactions |
| CLMEV-TICK-01 | Tick manipulation via precise swap amounts to cross specific ticks |
| CLMEV-TICK-02 | Gas griefing by forcing swaps through many initialized ticks |
| CLMEV-RANGE-01 | Range order sniping: observer copies profitable range positions |
| CLMEV-RANGE-02 | Narrow range LP position used as limit order, front-runnable |
| CLMEV-SANDWICH-01 | Concentrated liquidity amplifies sandwich profit vs V2 |
| CLMEV-COMPOUND-01 | Fee compounding front-run: attacker compounds right before large swap |
| CLMEV-ORACLE-01 | TWAP oracle manipulation cheaper with concentrated liquidity |
| CLMEV-ORACLE-02 | Observation array growth cost pushed to next user |
| CLMEV-MIGRATE-01 | V3→V4 migration: positions moved without optimal tick alignment |
| CLMEV-REBALANCE-01 | Auto-rebalance vault telegraphs trades, sandwichable |
| CLMEV-REBALANCE-02 | Rebalance threshold too tight, frequent unnecessary rebalances |
| CLMEV-FLASHLP-01 | Flash loan LP: add liquidity + swap + remove in one tx |
| CLMEV-FEE-01 | Fee tier arbitrage between pools with same token pair |
| CLMEV-POSVAL-01 | Position value calculation ignores impermanent loss |
| CLMEV-COLLECT-01 | Uncollected fees vulnerable to MEV extraction |
| CLMEV-LIMIT-01 | Limit order simulation via single-tick LP, no fill guarantee |

---

## 51 — CrossChainMessaging.sol

| # | Vulnerability |
|---|---|
| XMSG-LZ-REPLAY-01 | LayerZero message replayed on destination after nonce reset |
| XMSG-LZ-REMOTE-01 | Trusted remote address spoofed in cross-chain call |
| XMSG-WH-FORGE-01 | Wormhole VAA signature forged with compromised guardian |
| XMSG-WH-GUARDIAN-01 | Guardian set update not atomic, stale guardian accepted |
| XMSG-RELAY-CENSOR-01 | Relayer censors specific messages, no forced inclusion |
| XMSG-ORDER-01 | Message ordering not guaranteed, state applied out of sequence |
| XMSG-GAS-01 | Insufficient gas on destination, message marked delivered but reverted |
| XMSG-DOUBLESPEND-01 | Same message processed on two destination chains |
| XMSG-MINT-01 | Bridge mint without burn verification on source chain |
| XMSG-SRCVERIFY-01 | Source chain verification relies on block hash availability window |
| XMSG-REFUND-01 | Failed message refund goes to relayer instead of sender |
| XMSG-PAYLOAD-01 | Payload size exceeds max, silently truncated on destination |
| XMSG-MULTISIG-01 | Multisig threshold too low for bridge value at risk |
| XMSG-NONCE-01 | Nonce gap allows selective message skipping |
| XMSG-FEEEST-01 | Fee estimation off by 10x, user overpays or message stuck |
| XMSG-EXECUTOR-01 | Executor extracts MEV from cross-chain message ordering |
| XMSG-BLOCKED-01 | Blocked message path permanently locks user funds |
| XMSG-VERSION-01 | Message version upgrade breaks backward compatibility |
| XMSG-COMPOSED-01 | Composed message callback reenters send function |
| XMSG-DEFAULTCFG-01 | Default security config (1 confirmation) used instead of custom |

---

## 52 — DiamondProxy2535.sol

| # | Vulnerability |
|---|---|
| DIAMOND-COLLISION-01 | Function selector collision between facets |
| DIAMOND-STORAGE-01 | Storage slot collision between diamond storage namespaces |
| DIAMOND-INIT-01 | DiamondCut initializer not called, facet uninitialized |
| DIAMOND-UPGRADE-01 | Facet upgrade replaces critical function with malicious version |
| DIAMOND-REMOVE-01 | Removing facet leaves dangling storage that next facet reads |
| DIAMOND-FALLBACK-01 | Fallback function doesn't revert for unknown selectors |
| DIAMOND-LOOP-01 | Loupe functions iterate all facets, exceeds gas with many facets |
| DIAMOND-DELEGATE-01 | Delegatecall to facet writes to diamond's storage context |
| DIAMOND-OWNERSHIP-01 | Diamond ownership transfer has no two-step process |
| DIAMOND-FROZEN-01 | diamondCut disabled but facets still have admin functions |
| DIAMOND-IMMUTABLE-01 | Immutable function marked but no enforcement mechanism |
| DIAMOND-SELECTOR-01 | Selector computed differently between Solidity versions |
| DIAMOND-MULTICALL-01 | Multicall through diamond exposes cross-facet reentrancy |
| DIAMOND-INSPECT-01 | facetAddress() returns stale address after cut |
| DIAMOND-MULTIINIT-01 | Multiple init functions called in wrong order during cut |

---

## 53 — ModularAccounts7579.sol

| # | Vulnerability |
|---|---|
| MOD-VALIDATOR-01 | Validator module approves any userOp with crafted signature |
| MOD-EXECUTOR-01 | Executor module has unrestricted delegatecall |
| MOD-FALLBACK-01 | Fallback handler module intercepts ETH transfers |
| MOD-HOOK-01 | Pre-execution hook modifies calldata before validation |
| MOD-INSTALL-01 | Module installation doesn't verify ERC-7579 interface |
| MOD-UNINSTALL-01 | Uninstalled module retains storage access via dangling pointer |
| MOD-REGISTRY-01 | Module registry not checked, unaudited module installed |
| MOD-SELECTOR-01 | Module selector conflict with account core functions |
| MOD-RECURSIVE-01 | Module calls back into account, bypassing validation |
| MOD-STORAGE-01 | Module storage collides with account storage namespace |
| MOD-UPGRADE-01 | Module upgrade changes behavior without account owner consent |
| MOD-BATCH-01 | Batch execution partial failure leaves inconsistent state |
| MOD-GAS-01 | Module validation consumes excessive gas, griefing bundler |
| MOD-SESSION-01 | Session key module: permissions too broad, no spending limit |
| MOD-RECOVERY-01 | Recovery module social engineering, guardians compromised |
| MOD-PAYMASTER-01 | Paymaster module drains sponsorship funds via fake userOps |
| MOD-NONCE-01 | Two-dimensional nonce allows key-space collision |
| MOD-THRESHOLD-01 | Multi-sig threshold module: 1-of-N config effectively single signer |

---

## 54 — ChainlinkAutomation.sol

| # | Vulnerability |
|---|---|
| AUTO-GASCHECK-01 | checkUpkeep returns true even when performUpkeep will fail |
| AUTO-GASMANIP-01 | Gas price spike makes performUpkeep unprofitable for keepers |
| AUTO-INTERVAL-01 | Time-based trigger gamed by manipulating block timestamps |
| AUTO-LOGFILTER-01 | Log trigger filter too broad, triggers on irrelevant events |
| AUTO-REVERT-01 | performUpkeep reverts but upkeep remains active, wasting LINK |
| AUTO-BALANCE-01 | Upkeep LINK balance drained by rapid trigger spam |
| AUTO-SELFDOS-01 | checkUpkeep calls external contract that can DOS |
| AUTO-FRONTRUN-01 | Profitable action telegraphed by checkUpkeep, front-run before perform |
| AUTO-REGISTRY-01 | Registry migration leaves upkeeps in limbo between versions |
| AUTO-FORWARDER-01 | Forwarder contract spoofed by non-registry caller |
| AUTO-SIMGAS-01 | Simulation gas limit differs from execution, off-chain/on-chain mismatch |
| AUTO-CANCEL-01 | Cancelled upkeep still has pending perform in pipeline |
| AUTO-BATCH-01 | Batched performs: one revert kills entire batch |
| AUTO-OFFCHAIN-01 | Off-chain computation result not verified on-chain |
| AUTO-PREMIUM-01 | Gas premium set by registry, keeper extracts surplus |

---

## 55 — GasOptGoneWrong.sol

| # | Vulnerability |
|---|---|
| GASOPT-UNCHECKED-01 | Unchecked block hides overflow in token amount calculation |
| GASOPT-UNCHECKED-02 | Unchecked loop counter wraps to 0, infinite loop |
| GASOPT-ASSEMBLY-01 | Assembly sstore bypasses Solidity storage layout checks |
| GASOPT-ASSEMBLY-02 | Inline assembly mstore corrupts free memory pointer |
| GASOPT-CALLDATA-01 | Calldata used instead of memory for mutable parameter |
| GASOPT-PACKING-01 | Struct packing: writing one field corrupts adjacent packed field |
| GASOPT-PACKING-02 | Boolean packed with uint248, bit shift error flips wrong bits |
| GASOPT-SHORTCIRCUIT-01 | Short-circuit eval skips critical side-effect check |
| GASOPT-IMMUTABLE-01 | Immutable variable set in constructor from untrusted input |
| GASOPT-CONSTANT-01 | Constant expression evaluated differently across Solidity versions |
| GASOPT-BITMAP-01 | Bitmap index calculation off-by-one, wrong slot written |
| GASOPT-BITMAP-02 | 256-bit bitmap overflows when index >= 256 |
| GASOPT-CACHE-01 | Cached storage value stale after external call modified state |
| GASOPT-YULSTORAGE-01 | Yul sload/sstore raw slot collides with Solidity mapping |
| GASOPT-MSIZE-01 | Assembly reads msize(), affected by Solidity memory allocation |
| GASOPT-RETURNDATACOPY-01 | returndatacopy with wrong offset reads garbage |
| GASOPT-EMPTYCATCH-01 | Empty catch block swallows critical revert data |
| GASOPT-MINGAS-01 | 1/64th gas reservation rule: insufficient gas forwarded to subcall |
| GASOPT-CUSTOMTYPE-01 | User-defined value type wrapping skips overflow check |
| GASOPT-ABIPAD-01 | ABI encode/decode with dirty upper bits from assembly |

---

## 56 — YieldAggregator.sol

| # | Vulnerability |
|---|---|
| YIELD-MIGRATE-01 | Strategy migration moves funds but doesn't update accounting |
| YIELD-MIGRATE-02 | Migration during harvest creates uncounted yield |
| YIELD-HARVEST-01 | Harvest sandwich: front-run harvest → deposit → claim yield → withdraw |
| YIELD-HARVEST-02 | Harvest caller gets reward but vault share price not updated atomically |
| YIELD-STRATEGY-01 | Underlying strategy rug pulls, vault holds worthless receipts |
| YIELD-STRATEGY-02 | Strategy reports inflated totalAssets, artificially high share price |
| YIELD-DEPOSIT-01 | Deposit limit bypassed through multiple transactions |
| YIELD-DEPOSIT-02 | Deposit uses stale pricePerShare from before harvest |
| YIELD-WITHDRAW-01 | Withdrawal queue: first-mover advantage during bank run |
| YIELD-WITHDRAW-02 | Withdrawal fee not applied during emergency exit |
| YIELD-REBALANCE-01 | Rebalance between strategies creates arbitrage window |
| YIELD-REBALANCE-02 | Rebalance function permissionless, anyone triggers suboptimal allocation |
| YIELD-COMPOUND-01 | Auto-compound timing exploitable: compound right before deposit |
| YIELD-DEBT-01 | Strategy debt ratio exceeds available liquidity |
| YIELD-PERFORMANCE-01 | Performance fee calculated on unrealized gains |
| YIELD-MANAGEMENT-01 | Management fee accrues to governance token stakers, not vault depositors |
| YIELD-ERC4626-01 | ERC-4626 maxDeposit/maxWithdraw return wrong values |
| YIELD-FLASH-01 | Flash deposit → harvest → withdraw extracts pending yield |
| YIELD-MULTICHAIN-01 | Cross-chain yield aggregation: L2 yield not bridged back to L1 vault |
| YIELD-AUTOCOMP-01 | Auto-compounder sells reward token at manipulated DEX price |

---

## 57 — NFTLending.sol

| # | Vulnerability |
|---|---|
| NFTLEND-FLOOR-01 | Floor price from single DEX oracle, manipulable with thin liquidity |
| NFTLEND-APPRAISAL-01 | Individual token valuation relies on oracle reading on-chain traits — attacker inflates then reverts |
| NFTLEND-CASCADE-01 | One large liquidation drops floor → triggers cascade of more liquidations |
| NFTLEND-RARITY-01 | Rarity score updated by external oracle without freshness check |
| NFTLEND-WASHTRADE-01 | Last sale price used as floor reference — attacker wash trades at inflated price |
| NFTLEND-STALE-01 | Valuation cached and not refreshed before liquidation check |
| NFTLEND-ROYALTY-01 | Royalty fee on liquidation transfer makes liquidation unprofitable → bad debt |
| NFTLEND-P2PSNIPE-01 | Peer-to-peer offer visible on-chain, front-runnable by attacker with cheapest NFT |
| NFTLEND-TRANSFER-01 | Collection admin transfer function can move NFT out of lending protocol |
| NFTLEND-RATESPIKE-01 | Utilization-based interest rate spikes to 900%+ APR, forcing defaults |
| NFTLEND-SUBSTITUTE-01 | Collateral substitution without re-valuation — borrower swaps high-value for cheap NFT |
| NFTLEND-UNDERWATER-01 | Anyone can extend underwater loan to prevent protocol from liquidating |
| NFTLEND-FLASHNFT-01 | Flash-borrow NFT used as collateral during callback, returned but loan persists |
| NFTLEND-RUG-01 | Collection rug propagates bad debt — existing loans not force-liquidated |
| NFTLEND-METADATA-01 | Dynamic NFT metadata changes devalue collateral post-loan, no re-valuation triggered |

---

## 58 — VyperCompatBugs.sol

| # | Vulnerability |
|---|---|
| VYPER-REENTER-01 | Vyper 0.2.x @nonreentrant lock bypass through cross-function reentrancy |
| VYPER-RAWCALL-01 | Vyper raw_call() return value ignored, silent failure |
| VYPER-SLICE-01 | Vyper slice() reads past buffer boundaries (CVE 0.3.1) |
| VYPER-CURVE-01 | Curve-style pool reentrancy through ETH callback in remove_liquidity (July 2023) |
| VYPER-STORAGE-01 | Vyper/Solidity storage layout mismatch in proxy: reversed key.slot order |
| VYPER-DEFAULT-01 | Vyper __default__() has side effects that Solidity callers don't anticipate |
| VYPER-COMPILER-01 | Mixed Vyper compiler versions (0.2.x/0.3.x/0.4.x) with different ABI encoding |
| VYPER-ABI-01 | Vyper multi-return values encoded differently in older versions |
| VYPER-OVERFLOW-01 | Vyper pre-0.3.4 lacked overflow checks, Solidity trusts result as safe |
| VYPER-MODIFIER-01 | @nonreentrant groups only protect same-key functions — cross-group reentry |
| VYPER-RETURN-01 | Empty return padding: Vyper void functions return 0 bytes, Solidity expects bool |
| VYPER-DYNARRAY-01 | Vyper DynArray length corruption in 0.3.x, Solidity reads wrong length from storage |
| VYPER-SELFDESTRUCT-01 | Vyper selfdestruct accessible in older versions, EIP-6780 behavior change |
| VYPER-CREATE2-01 | Create2 front-running: attacker deploys malicious version at predicted address |
| VYPER-BOOLPACK-01 | Boolean packing order differs between Vyper/Solidity, cross-contract proxy corruption |

---

## 59 — EigenLayerAVS.sol

| # | Vulnerability |
|---|---|
| EIGEN-COLLUSION-01 | Multiple operators controlled by same entity reach quorum alone |
| EIGEN-QUORUM-01 | Quorum counts by operator count not stake weight — Sybil-attackable |
| EIGEN-MIDDLEWARE-01 | Middleware registration doesn't verify actual AVS interface |
| EIGEN-SLASH-01 | Slashing conditions vague, no on-chain evidence verification, no appeal |
| EIGEN-WITHDRAW-01 | Withdrawal delay: operator slashed during delay but amount not reduced |
| EIGEN-DELEGATION-01 | Delegation shares double-counted for both staker and operator |
| EIGEN-STRATEGY-01 | Strategy deposit with ERC777 callback enables reentrancy |
| EIGEN-METADATA-01 | Operator metadata self-reported hash, delegators trust without verification |
| EIGEN-DOUBLEDIP-01 | Same ETH staked across multiple AVS services simultaneously |
| EIGEN-UNDERCOLAT-01 | AVS claims more security than actually restaked |
| EIGEN-TASKFORGE-01 | Task responses don't require BLS signature or cryptographic proof |
| EIGEN-FEESPLIT-01 | Operator sets 100% fee split, no time-lock, steals restaking rewards |
| EIGEN-DEREG-01 | Operator deregisters right before slashing tx — front-run avoidance |
| EIGEN-POD-01 | EigenPod balance desync: oracle reports inflated beacon chain balance |
| EIGEN-DILUTION-01 | Shared security diluted as more AVS services onboard |
| EIGEN-KEYROT-01 | Old signing key remains valid during rotation — compromised key still signs |
| EIGEN-BEACON-01 | Beacon chain oracle lag: validator slashed but restaking protocol still counts stake |
| EIGEN-MIGRATE-01 | M1→M2 migration credits shares without burning M1 position |

---

## 60 — BlobEIP4844.sol

| # | Vulnerability |
|---|---|
| BLOB-FEEMARKET-01 | Blob gas price pumped by filling all 6 blob slots per block |
| BLOB-KZG-01 | KZG commitment verification not enforced on-chain — fake commitments accepted |
| BLOB-DASAMPLE-01 | DA sampling relies on honest majority, colluding validators attest without downloading |
| BLOB-DOS-01 | Max 6 blobs per block: attacker reserves all slots at near-zero cost |
| BLOB-L2COST-01 | L2 sequencer passes blob costs using stale price, absorbs loss |
| BLOB-GASSPIKE-01 | Exponential blob gas pricing: 10 full blocks → 12x price increase |
| BLOB-COMMITREUSE-01 | Same KZG commitment reused across multiple submissions |
| BLOB-EXPIRY-01 | Blob data pruned after ~18 days — fraud proof impossible after expiry |
| BLOB-ATOMICITY-01 | Multi-blob batch: partial inclusion if one blob censored |
| BLOB-PROOFTTL-01 | Proof window can exceed blob TTL with extensions — auto-finalize fraud |
| BLOB-EXCESSGAS-01 | Excess blob gas tracking manipulated across block boundaries |
| BLOB-PRECOMPILE-01 | Point evaluation precompile input format wrong version byte |
| BLOB-TYPE3-01 | Type 3 transaction encoding different from Type 2, contract can't distinguish |
| BLOB-VHASH-01 | Versioned hash collision resistance reduced to 248 bits |
| BLOB-CENSOR-01 | Blob sidecar censorship by builders, no forced inclusion mechanism |

---

## 61 — AdvancedSignatures.sol

| # | Vulnerability |
|---|---|
| SIG-DOMAIN-01 | EIP-712 DOMAIN_SEPARATOR cached in constructor — invalid after chain fork |
| SIG-1271FAKE-01 | Malicious contract always returns 0x1626ba7e for any hash/signature pair |
| SIG-PERMITREPLAY-01 | Permit signature from mainnet replayed on L2 with same contract address |
| SIG-MALLEABLE-01 | ecrecover accepts both s-values — attacker flips s for second valid signature |
| SIG-ECRECOVER0-01 | ecrecover returns address(0) for invalid sig; if owner == 0x0, auth bypassed |
| SIG-PERMITFRONT-01 | Permit tx visible in mempool, attacker extracts sig and front-runs |
| SIG-NONCEGAP-01 | Anyone can increment nonce to invalidate pending permits |
| SIG-DEADLINE-01 | Permit with type(uint256).max deadline never expires — permanent exposure |
| SIG-MULTISIGREORG-01 | Multi-sig approval not replay-protected across reorgs |
| SIG-ISVALID-01 | Upgradeable wallet changes isValidSignature implementation post-signing |
| SIG-TYPEHASH-01 | Different struct types produce identical typeHash — cross-action replay |
| SIG-OFFCHAIN-01 | Off-chain signature replay check uses sig hash not message hash |
| SIG-COMPACT-01 | EIP-2098 compact signature v-recovery from vs high bit fails without mask |
| SIG-METATX-01 | Relayer controls gas limit for inner call — sig burned but tx dropped |
| SIG-BATCHPERMIT-01 | Batch permit: one invalid sig reverts entire batch — front-run griefing |
| SIG-CHECKER-01 | SignatureChecker swallows OOG as "invalid" instead of propagating revert |
| SIG-CREATE2SIG-01 | CREATE2 predictable address: crafted signature where signer == future contract |
| SIG-SCOPE-01 | Delegated action scope stored but never enforced during execution |

---

## 62 — LibCloneExploits.sol

| # | Vulnerability |
|---|---|
| CLONE-UNINIT-01 | Clone deployed but initialize() not called atomically — anyone can claim ownership |
| CLONE-UPGRADE-01 | Changing implementation only affects future clones, existing break if new layout differs |
| CLONE-COLLISION-01 | Deterministic CREATE2 clone address — attacker front-runs or redeploys malicious code |
| CLONE-FRONTINIT-01 | Initialize function permissionless — front-run between deploy and init |
| CLONE-STORAGE-01 | Clone's implementation does delegatecall internally, corrupting clone storage |
| CLONE-IMMARG-01 | ClonesWithImmutableArgs: large args + impl bytecode exceeds 24KB contract limit |
| CLONE-DESTRUCT-01 | Selfdestruct on implementation kills ALL clones using delegatecall |
| CLONE-METAMORPHIC-01 | CREATE2 + selfdestruct + redeploy = different code at same address |
| CLONE-BEACON-01 | Changing beacon changes ALL beacon proxies instantly, no per-clone opt-in |
| CLONE-INITREPLAY-01 | Initialize callable multiple times — attacker re-initializes to change owner |
| CLONE-DELCHAIN-01 | Three-level delegatecall chain: clone → impl → lib — storage context mismatch |
| CLONE-BYTECODE-01 | Clone bytecode verification only checks 20 bytes, doesn't verify full EIP-1167 pattern |
| CLONE-TRUNCATE-01 | Reading immutable args from clone bytecode with wrong offset reads proxy code as data |
| CLONE-FACTORY-01 | Factory permissionless: anyone creates clone pointing to malicious implementation |
| CLONE-IDENTITY-01 | Clone's address(this) ≠ implementation — external contracts may trust clone as impl |

---

## 63 — LeveragedVault.sol

| # | Vulnerability |
|---|---|
| LEV-RECURSE-01 | Recursive deposit-borrow loop compounds leverage beyond intended limit |
| LEV-LIQPRICE-01 | Liquidation uses spot oracle price, flash-loan manipulable |
| LEV-RATIOOVERFLOW-01 | Leverage calculation overflow: debt > collateral causes underflow → huge ratio |
| LEV-FLASHLEV-01 | Flash loan creates leveraged position without own capital |
| LEV-DELEVSANDWICH-01 | Deleverage involves DEX swap, sandwichable for worse execution |
| LEV-COLFACTOR-01 | Collateral factor change instantly makes positions liquidatable, no time-lock |
| LEV-BADDEBT-01 | Bad debt socialized to all depositors — whale self-liquidates to spread loss |
| LEV-ORACLELEV-01 | Position opened at stale oracle price, profited when oracle updates |
| LEV-INTERESTSKIP-01 | Interest only accrues when position touched — effective rate below stated |
| LEV-TOKENDEPEG-01 | Leverage token depegs from NAV during volatility — death spiral |
| LEV-AUTODELFAIL-01 | Auto-deleverage fails during gas spike — keepers can't afford calls |
| LEV-MARGINCALL-01 | 24-hour margin call grace period: price crashes further, huge bad debt |
| LEV-COLCHAIN-01 | Collateral is receipt token from another protocol — underlying exploit makes it worthless |
| LEV-WITHDRAWLEV-01 | Partial withdrawal from leveraged position without health factor check |
| LEV-SIZEAMP-01 | Multiple positions compound: no per-user total exposure limit |
| LEV-FUNDDRAIN-01 | Funding rate set by oracle not market — manipulated to drain one side |
| LEV-MIGDESYNC-01 | Strategy migration while positions open — new strategy has different pricing |
| LEV-HEALTHROUND-01 | Health factor integer division loses precision at extreme leverage |

---

## 64 — TokenMigration.sol

| # | Vulnerability |
|---|---|
| MIGRATE-DOUBLECLAIM-01 | Claim flag not set per migration — user migrates, buys more V1, migrates again |
| MIGRATE-SNAPSHOT-01 | Snapshot block announced in advance — flash-loan to inflate balance at snapshot |
| MIGRATE-MERKLE-01 | Merkle proof doesn't include nonce; multiple leaves per user enable multi-claim |
| MIGRATE-RATE-01 | Migration rate changeable mid-migration — insider sets high rate for own tokens |
| MIGRATE-LEFTOVER-01 | Rescue function drains V2 reserve before migration completes |
| MIGRATE-V1ACTIVE-01 | V1 token not paused after migration — cheap V1 bought and migrated to V2 |
| MIGRATE-BRIDGE-01 | Cross-chain migration bridge proof not verified — attacker claims on both chains |
| MIGRATE-SYBIL-01 | Flat airdrop per address: attacker creates 10,000 addresses |
| MIGRATE-VESTING-01 | Migration resets vesting schedule — 80% vested in V1 becomes 0% in V2 |
| MIGRATE-DEADLINE-01 | Deadline extendable indefinitely by owner — persistent price uncertainty |
| MIGRATE-XCHAIN-01 | Same tokens migrated on two chains simultaneously, bridge latency exploited |
| MIGRATE-SUPPLY-01 | V2 supply exceeds max when migration + airdrop + vesting combined |
| MIGRATE-GOVPOWER-01 | Voting power = V1 balance + V2 balance during transition — double governance |
| MIGRATE-FEETRANSFER-01 | Fee-on-transfer V1 token: less arrives than expected but V2 minted on full amount |
| MIGRATE-PERMITSIG-01 | V1 permit signature replays on V2 if same name/version/address |

---

## 65 — PaymentSplitter.sol

| # | Vulnerability |
|---|---|
| PAY-PUSHPULL-01 | Push payment to all payees: one reverting recipient blocks entire distribution |
| PAY-DILUTE-01 | Owner adds new payee, diluting existing payees without consent |
| PAY-ROUNDING-01 | Integer division leaves dust that accumulates and is locked forever |
| PAY-ETHDESYNC-01 | ETH and ERC20 tracked separately; share change desyncs ERC20 claims |
| PAY-REENTER-01 | ETH released before state update — reentrancy drains funds |
| PAY-ZEROSHARE-01 | Payee with 0 shares added, wastes gas in distribution loops |
| PAY-DYNSHARE-01 | Shares modified after revenue accumulation — increase shares before claiming historical |
| PAY-TIMING-01 | Claim timing between revenue deposits exploitable with share manipulation |
| PAY-MULTITOKEN-01 | Multi-token claim: one 0-owed token reverts entire batch |
| PAY-ROYALTYBYPASS-01 | NFT marketplace bypasses royalties — expected payment never arrives |
| PAY-GASLIMIT-01 | 2300 gas stipend for payee transfer — contracts needing more gas silently skipped |
| PAY-UNCLAIMED-01 | Unclaimed funds expired by owner, redistributed to active payees including owner |
| PAY-FLASHSHARE-01 | Flash-borrow shares: transfer → claim revenue → transfer back in one tx |
| PAY-DELEGATETHEFT-01 | Owner delegatecall to arbitrary contract transfers all funds out |
| PAY-PERCENTOVERFLOW-01 | Enough payees at max shares overflows totalShares |

---

## 66 — ZKCoprocessor.sol

| # | Vulnerability |
|---|---|
| ZK-PROOFBYPASS-01 | Verifier call result not decoded — staticcall success ≠ proof validity |
| ZK-PUBINPUT-01 | Public inputs not validated against expected format — result hash mismatch |
| ZK-KEYROTATION-01 | Old verification key still accepted after rotation — proofs persist |
| ZK-GROTH16MAL-01 | Groth16 proof malleability: (-A, -B) produces different bytes, same verification |
| ZK-TRUSTEDSETUP-01 | Trusted setup compromise: toxic waste enables proof forgery |
| ZK-HASHEXPLOIT-01 | SNARK circuit uses Poseidon but on-chain uses keccak256 — hash mismatch |
| ZK-PROOFREPLAY-01 | Proof valid on any contract with same verifier — no instance binding |
| ZK-RECDEPTH-01 | Recursive proof chain: 10 verifications × 300k gas approaches block limit |
| ZK-WITNESS-01 | Private witness extractable by brute-forcing small search space |
| ZK-AGGSPLIT-01 | Aggregated proof: individual result binding not checked — substitution attack |
| ZK-COPTRUST-01 | Coprocessor result trusted without bounds checking — overflow in consumer |
| ZK-GASDOS-01 | Proof with 10,000 public inputs exceeds block gas limit |
| ZK-FIATSHAMIR-01 | Weak Fiat-Shamir: challenge not recomputed — prover chooses convenient challenge |
| ZK-NULLPROOF-01 | Empty proof bytes accepted as valid |
| ZK-VERUPGRADE-01 | Upgradeable verifier contract: malicious upgrade returns true for all proofs |
| ZK-BATCHBAD-01 | One invalid proof in batch rejects all — attacker griefs others' proofs |
| ZK-PROVERCENSOR-01 | Only authorized provers: if all collude or go offline, protocol halts |
| ZK-OFFCHAIN-01 | Off-chain computation uses different field arithmetic — results diverge near 2^256 |

---

## 67 — InsuranceFund.sol

| # | Vulnerability |
|---|---|
| INS-FALSECLAIM-01 | Claim approved by assessors without on-chain exploit verification |
| INS-ORACLECLAIM-01 | Parametric insurance triggered by manipulated oracle price via flash loan |
| INS-PREMIUMDRAIN-01 | Underwriters withdraw premiums before claims settled — fund can't pay |
| INS-INSOLVENCY-01 | Total coverage sold exceeds available capital — single large claim = insolvent |
| INS-GOVVOTE-01 | Claim approval by deposit-weighted vote — one whale controls all approvals |
| INS-STACKING-01 | Same user buys N policies for same protocol, claims on all N |
| INS-RETROACTIVE-01 | Coverage purchased after exploit but before public disclosure |
| INS-ASSESSOR-01 | 3 of 5 assessors collude to approve false claims and split proceeds |
| INS-PREMIUMFRONT-01 | Premium calculation oracle-based — front-run to buy cheap coverage pre-exploit |
| INS-CAPEFFICIENCY-01 | Underwriter capital used as collateral elsewhere — double-committed |
| INS-REINSURANCE-01 | Circular reinsurance: A insures B insures A — both insolvent on same event |
| INS-EXPLOIT2CLAIM-01 | Attacker is the exploiter: exploit + insurance claim = double profit |
| INS-TIMECLAIM-01 | Claim grace period: auto-approve after expiry if not resolved |
| INS-PARAMETRIC-01 | TVL drop trigger spoofed by temporarily withdrawing liquidity |
| INS-SHIELDMINE-01 | Shield mining rewards exceed premium — pure yield farming with no insurance intent |

---

## Cross-Contract Chain Links

| Source | Targets |
|---|---|
| 01 PrecisionVault | → 10, 20, 21 (share inflation cascades) |
| 02 AuthorityChain | → 11, 18, 19, 22 (transitive delegation abuse) |
| 03 GhostStateOracle | → 07, 09, 17, 19, 20, 24, 27 (stale cached price) |
| 04 TemporalLock | → 13 (transient flash loan bypass) |
| 06 CallbackReentrancy | → 13, 18, 25 (token callback chains) |
| 07 FlashLoanVictim | → 03, 09, 15, 16, 18, 21, 23 (flash-manipulable price) |
| 09 CrossContractDesync | → 01, 07 (stale snapshot + flash price) |
| 11 Create2Metamorphic | → 02, 25 (metamorphic trust persistence) |
| 13 TransientStorageLeak | → 04, 06, 22 (cross-call transient leak) |
| 14 SequencerDownOracle | → 16, 17, 23, 24, 26 (sequencer-down fallback) |
| 15 SandwichableView | → 07, 23, 26 (manipulable rate as oracle) |
| 16 ZKProofMalleability | → 03, 07, 14, 17, 19, 27 (stale root + flash state) |
| 17 L2SequencerExploit | → 03, 14, 16, 19, 26 (L2 challenge bypass) |
| 18 AccountAbstractionVuln | → 02, 06, 07, 12, 25 (bundler MEV + callbacks) |
| 19 BridgeOracleManipulation | → 02, 03, 16, 17, 24, 26 (guardian + stale price) |
| 20 RestakingSlashingCascade | → 01, 03, 07, 19 (cascade + share inflation + stale price) |
| 21 TokenPoisoning | → 01, 06, 07 (share inflation + callback + flash) |
| 22 PectraExploits | → 02, 12, 13 (delegation + dirty bits + transient) |
| 23 IntentMEV | → 07, 14, 15 (flash oracle + sequencer + sandwich) |
| 24 RWAOracleDesync | → 03, 14, 19, 22 (stale NAV + compliance bridge) |
| 25 TokenBoundAccounts | → 06, 08, 11, 18 (callback + proxy + metamorphic + AA) |
| 26 PreconfBasedRollup | → 15, 17, 19, 23 (sequencer + bridge + intent) |
| 27 AIFHESocialRecovery | → 03, 16, 18, 24, 25 (AI oracle + FHE + recovery chains) |
| 68 OptimismDisputeGame | → 17, 19, 69 (dispute game + bond logic + withdrawal) |
| 69 OptimismWithdrawalBridge | → 35, 51, 68 (withdrawal proof + cross-domain msg) |
| 70 OptimismTimingExploit | → 17, 68, 69 (timing + sequencer window + clock) |

---

## 68 — OptimismDisputeGame.sol

| # | Vulnerability |
|---|---|
| DISPUTE-01 | Clock manipulation — duration check uses < not <=, bypasses CLOCK_EXTENSION |
| DISPUTE-02 | Grandparent clock inheritance — getChallengerDuration uses grandparent without min check |
| DISPUTE-03 | Invalid move accepted — no claim validation on attack/defend |
| DISPUTE-04 | Execution bisection — vm().step without preimage verification |
| DISPUTE-05 | Bond bypass — getRequiredBond called but NOT enforced via require |
| DISPUTE-06 | Grandchild bond distribution skipped — only direct children resolved |
| DISPUTE-07 | Resolution race condition — no status check, no mutex |
| DISPUTE-08 | Root claim countered by uncountered counter — recursive resolution missing |
| DISPUTE-09 | Split depth exploitation — no _verifyExecBisection at SPLIT_DEPTH boundary |
| DISPUTE-10 | Max game depth exceeded — no GameDepthExceeded revert |
| DISPUTE-11 | Preimage manipulation — loadPreimage without keccak256 check |
| DISPUTE-12 | VM step witness forgery — vm().step return value ignored |
| DISPUTE-13 | Credit theft — claimCredit has no access control |
| DISPUTE-14 | Parent index manipulation — no bounds check on parentIndex |
| DISPUTE-15 | Root claim mutation — rootClaim is NOT immutable |
| DISPUTE-16 | Anchor state not validated — extraData not checked against registry |
| BOND-01 | Bond calculation overflow — BASE_BOND * 2^depth can overflow |
| BOND-02 | Bond escalation by depth without bounds — no max cap |
| BOND-03 | Distribution accounting error — credit += without CEI pattern |
| BOND-04 | Wrong party on resolution — recipient = claimant instead of winner |
| BOND-05 | Insufficient bond check — msg.value not required >= getRequiredBond |
| BOND-06 | Split depth bond bypass — no escalation at SPLIT_DEPTH boundary |
| BOND-07 | Double claim credit — state update AFTER external ETH transfer |
| BOND-08 | Subgame re-resolution — resolvedSubgames check missing |
| BOND-09 | Credit overflow — credit accounting without SafeMath |
| BOND-10 | Credit addition overflow — silent wraparound |
| BOND-11 | DelayedWETH drain — unlock callable by unauthorized party |
| BOND-12 | Unlock timing manipulation — DELAY_SECONDS not enforced |
| BOND-13 | Griefing via MIN_BOND — 0.001 ETH enables spam attacks |
| BOND-14 | MAX_GAME_DEPTH allows 2^73 bond escalation |
| BOND-15 | Refund calculation error — excess bond not returned |
| BOND-16 | Refund reentrancy — ETH transfer before state update |

---

## 69 — OptimismWithdrawalBridge.sol

| # | Vulnerability |
|---|---|
| WD-01 | Merkle proof bypass — SecureMerkleTrie.verifyInclusionProof not robust |
| WD-02 | encodePacked length extension — abi.encodePacked hash collision |
| WD-03 | Unchecked output root — outputRoot not verified against L2OutputOracle |
| WD-04 | Output root used pre-finalization — no FINALIZATION_PERIOD check |
| WD-05 | Unauthorized proposer — proposeL2Output has no access control |
| WD-06 | Finalization timestamp bypass — wrong comparison direction |
| WD-07 | L2 timestamp validation missing — output.timestamp not validated |
| WD-08 | Finalization skip — CEI violation, state after call |
| WD-09 | Re-prove withdrawal — provenWithdrawals can be overwritten |
| WD-10 | Not marked finalized — only set on success, retry possible |
| WD-11 | Hash missing unique ID — no chainid/portal address in withdrawalHash |
| WD-12 | Proof reuse — failed withdrawal can be re-finalized |
| WD-13 | Storage proof forgery — no re-verification at finalization |
| WD-14 | L2 block number not validated against output |
| WD-15 | Disputed game output accepted — no game status check |
| MSG-01 | Cross-chain replay — no chain ID in message hash |
| MSG-02 | Sender not validated — xDomainMsgSender spoofable |
| MSG-03 | Hash missing nonce — hashCrossDomainMessage omits nonce |
| MSG-04 | Nonce manipulation — _nonce parameter not verified against counter |
| MSG-05 | Relayer context manipulation — msg.sender (relayer) unscreened |
| MSG-06 | Gas limit bypass — _minGasLimit can be 0 |
| MSG-07 | Failed message re-execution — infinite retries, no rate limit |
| MSG-08 | Successful message tracking — uses wrong hash for dedup |
| MSG-09 | Version mismatch — MESSAGE_VERSION not included in hash |
| MSG-10 | Versioned encoding missing — no encodeVersionedNonce |
| MSG-11 | Target validation missing — allows self-calls |
| MSG-12 | Sender spoofing — xDomainMsgSender not reset after call |
| MSG-13 | Value mismatch — msg.value != _value not checked |
| MSG-14 | Callback reentrancy — no reentrancy guard on relayMessage |
| MSG-15 | Message queue manipulation — no ordering, LIFO not FIFO |
| MSG-16 | Withdrawal logging incomplete — missing fields in hash |

---

## 70 — OptimismTimingExploit.sol

| # | Vulnerability |
|---|---|
| TIME-01 | Timestamp without buffer — block.timestamp < deadline, no safety margin |
| TIME-02 | Exact timestamp comparison — block.timestamp == value exploitable |
| TIME-03 | L1/L2 desync — drift check uses SEQUENCER_WINDOW_SIZE not MAX_SEQUENCER_DRIFT |
| TIME-04 | Sequencer window without drift subtraction — 1h window instead of 50min |
| TIME-05 | Deadline bypass — strict < allows execution at exact boundary |
| TIME-06 | Block number deadline — L1/L2 block time mismatch |
| TIME-07 | Short challenge period — 12 hours instead of 7 days |
| TIME-08 | Short finalization period — 2 days instead of 7 days |
| TIME-09 | Sequencer status unchecked — critical operations without isSequencerActive |
| TIME-10 | Forced inclusion timing — lastActiveTimestamp manipulable |
| TIME-11 | Clock duration no minimum — _duration can be 0 (instant timeout) |
| TIME-12 | Clock inheritance exploit — extension exceeds MAX_CLOCK_DURATION |
| TIME-13 | Resolution race condition — no mutex on resolve/finalize |
| TIME-14 | Game status non-atomic — check-then-act pattern exploitable |
| TIME-15 | Proof maturity bypass — wrong comparison direction returns true before maturity |
| TIME-16 | Challenge deadline too short — 12h challenge period insufficient |
| TIME-17 | Batch ordering — batches accepted out of order |
| TIME-18 | Batch timestamp validation missing — epochTimestamp not cross-checked with L1 |
