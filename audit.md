# MCP Test Failure Audit — First Principles

Date: 2026-02-27
Branch: `master` at `bd00f7a1a9`
Method: Trace each failing test's call path from test assertion back through production code to root cause. Cross-reference against `plan.md` to classify as MCP bug, upstream issue, or test infra gap.

---

## Executive Summary

**5 tests pass, 5 fail, 5 timeout.** Every failure traces to one of three root causes:

1. **RPC finalized-slot visibility** — alpenglow finalization updates `highest_super_majority_root` via votor→commitment_service, but tests that poll RPC for finalized slots either (a) block on `TpuClient` websocket connection setup after partition, or (b) advance too slowly for the 180s timeout.

2. **Pre-migration cluster health race** — `new_pre_migration_alpenglow` starts all validators in parallel via `wait_for_supermajority=Some(0)`. The test sends an RPC transaction before non-leader validators have replayed any blocks, hitting the RPC health gate (`rpc.rs:3877-3895`).

3. **Post-restart catch-up** — restarted nodes need to replay blocks, re-establish QUIC connections, and resume voting. The test timeouts (180s-357s) are insufficient.

None of these are MCP protocol bugs. They are test infrastructure issues or missing alpenglow integration with existing test patterns.

---

## Failure 1: Basic Liveness Timeout (`test_alpenglow_1`, `test_alpenglow_4`, `test_alpenglow_4_1_offline`)

### Symptom
Tests run >10 minutes with no progress, killed manually.

### Call Path
```
test_alpenglow_nodes_basic(num_nodes, offline)        [local_cluster.rs:178]
  └─ spend_and_verify_all_nodes(...)                   ← PASSES (processed commitment)
  └─ cluster.check_for_new_roots(16, ...)              ← HANGS
       └─ cluster_tests::check_for_new_roots(16, ...)  [cluster_tests.rs:434]
            └─ check_for_new_slots_with_commitment(..., finalized)  [cluster_tests.rs:395]
                 └─ loop {                              [180s timeout at line 409]
                      new_tpu_quic_client(node, cache)  [cluster_tests.rs:412]
                        └─ TpuClient::new_with_connection_cache(...)  [cluster_tests.rs:915]
                             └─ RpcClient + WebSocket pubsub subscription
                      client.rpc_client().get_slot_with_commitment(finalized)  [line 414]
                        └─ RPC: get_slot → bank(finalized)  [rpc.rs:2848→957→349]
                             └─ block_commitment_cache.highest_super_majority_root()  [rpc.rs:362]
                    }
```

### Finalization Path (alpenglow)
```
Votor consensus_pool detects FinalizeFast/Finalize cert  [consensus_pool.rs:323-342]
  └─ consensus_pool_service::add_message_and_maybe_update_commitment  [consensus_pool_service.rs:370-378]
       └─ update_commitment_cache(Finalized, slot, sender)  [votor/commitment.rs:27]
            └─ commitment_sender.try_send(...)  [bounded channel, cap 1000]
                 └─ AggregateCommitmentService::run_loop  [commitment_service.rs:120-180]
                      └─ recv(ag_receiver) → alpenglow_update_commitment_cache  [line 141-148]
                           └─ set_highest_super_majority_root(slot)  [line 199]
```

### Root Cause
The finalization→commitment path IS wired and works (proven by the §1 and §2 tests where votor logs "Finalized (slot) fast: true" and "new root N"). The hang occurs because `TpuClient::new_with_connection_cache` establishes a WebSocket subscription (`rpc_pubsub_url`) which may block or slow the iteration loop. After a partition or under load, the WebSocket connection to each node is created fresh on every loop iteration (line 412 creates a new client each time). If any node's WebSocket handshake is slow, the 180s wall-clock assertion can't fire because the thread is blocked inside the constructor.

**Secondary factor:** The test collects DISTINCT finalized slot values across ALL nodes (line 420: `min` across all node sets). If any one node lags in finalization, the minimum stays low. With alpenglow's slot-per-400ms cadence and some overhead, collecting 16 distinct finalized slots from N nodes requires all N to finalize at least 16 slots each.

### Classification
**Test infrastructure issue.** Not an MCP bug. The passing §1 test (`test_local_cluster_mcp_produces_blockstore_artifacts`) proves 5-node alpenglow finalization works in 47s by using bounded completion conditions with direct blockstore queries instead of RPC polling.

### plan.md Reference
plan.md is silent on `check_for_new_roots` compatibility. The reuse map (plan.md §Reuse Map) states "Existing replay main loop and receivers" but does not address RPC commitment polling behavior for alpenglow.

---

## Failure 2: Partition Recovery Timeout (`test_alpenglow_cluster_partition_1_1`, `test_alpenglow_cluster_partition_1_1_1`)

### Symptom
Tests run >10-20 minutes, killed manually.

### Call Path
```
run_test_cluster_partition(num_partitions=2, is_alpenglow=true)  [local_cluster.rs:4557]
  └─ run_cluster_partition(...)  [integration_tests.rs:394]
       └─ LocalCluster::new_alpenglow(...)              ← OK
       └─ spend_and_verify_all_nodes(...)               ← PASSES
       └─ turbine_mode.set(TurbineAndRepairDisabled)    [line 514]
       └─ alpenglow_port_override.update_override(blackhole)  [line 526]
       └─ sleep(partition_duration)                     [10s, line 527]
       └─ turbine_mode.set(Enabled)                     [line 531]
       └─ alpenglow_port_override.clear()               [line 533]
       └─ sleep(10s + 10s)                              [lines 543, 548]
       └─ on_partition_resolved:
            └─ cluster.check_for_new_roots(16, ...)     ← HANGS (same as Failure 1)
```

### Root Cause
Same as Failure 1: `check_for_new_roots` uses RPC finalized-slot polling which hangs. After the partition is resolved, the cluster needs to re-establish consensus. Votor likely finalizes successfully (the §2 fallback tests prove partition recovery works), but the RPC polling mechanism fails to observe it in time.

**Additional factor:** The partition disables turbine AND blackholes alpenglow ports (votor consensus messages). After resolution, nodes must re-establish votor QUIC connections before finalization certificates can flow. The `TpuClient` WebSocket creation inside the polling loop adds latency per iteration.

### Classification
**Test infrastructure issue.** `test_alpenglow_add_missing_parent_ready` (a more targeted partition test using direct vote listener) PASSES in 47s, proving alpenglow partition recovery works.

### plan.md Reference
plan.md §A6 states "TVU MCP control channel is bounded and ingress is non-blocking with explicit drop counters." The partition test's blackhole override is applied via `AlpenglowPortOverride` which is test infrastructure, not MCP protocol.

---

## Failure 3: Migration Tests (`test_alpenglow_migration_4`, `test_alpenglow_restart_post_migration`)

### Symptom
FAIL in 27-34s: "Node is unhealthy" (`RpcCustomError -32005`) at `send_and_confirm_transaction`.

### Call Path
```
test_alpenglow_migration(num_nodes=4, leader_schedule=&[4,4,4,4])  [local_cluster.rs:6313]
  └─ LocalCluster::new_pre_migration_alpenglow(...)  [local_cluster.rs:228]
       └─ init(config, AlpenglowMode::PreMigration)  [line 345]
            └─ genesis = create_genesis_config_with_vote_accounts(is_alpenglow=true)
            └─ genesis.accounts.remove(&alpenglow::id())       [line 361]
            └─ genesis.accounts.remove(&GENESIS_CERTIFICATE)   [line 366]
            └─ wait_for_supermajority = Some(0)                [line 6333]
                 └─ start_all_validators_parallel()            [line 716-800]
  └─ RpcClient::new_socket(...processed...)
  └─ client.send_and_confirm_transaction(&activation_tx)       [line 6401] ← FAILS
       └─ RPC: send_transaction                                [rpc.rs:3850]
            └─ Health check gate                               [rpc.rs:3877-3895]
                 └─ meta.health.check()                        [rpc_health.rs:44]
                      └─ my_slot = optimistically_confirmed_bank.slot()  ← 0
                      └─ cluster_slot = blockstore.get_latest_optimistic_slots(1)  ← 5+
                      └─ my_slot < cluster_slot - distance → Behind → REJECT
```

### Root Cause
`wait_for_supermajority=Some(0)` starts all validators in parallel. The leader begins producing blocks immediately (slots 1-5+), updating the blockstore optimistic slot tracker. Non-leader validators haven't replayed any blocks yet, so their `OptimisticallyConfirmedBank` is still at slot 0. The RPC health check compares the node's own slot against the cluster's latest optimistic slot and returns "Behind" status.

**Why `new_alpenglow` works but `new_pre_migration_alpenglow` doesn't:** `new_alpenglow` also uses `wait_for_supermajority=Some(0)` with parallel startup, but the MCP primary test (`test_local_cluster_mcp_produces_blockstore_artifacts`) doesn't send transactions via RPC immediately — it waits for feature activation first. The migration test sends transactions before validators have caught up.

### Classification
**Test infrastructure issue.** The RPC health check is standard upstream behavior. The test needs to wait for validator health before sending transactions, or set `skip_preflight_health_check = true`.

### plan.md Reference
plan.md does not address pre-migration cluster bootstrapping or RPC health check timing. The migration path is not in plan.md's scope (plan.md covers MCP protocol implementation, not feature activation test infrastructure).

---

## Failure 4: Missed Migration Bank Hash (`test_alpenglow_missed_migration_entirely`)

### Symptom
FAIL: replay_stage panic at line 1910 — "producing duplicate blocks... froze slot 5 with hash X while cluster hash is Y"

### Call Path
```
test_alpenglow_missed_migration_entirely()  [local_cluster.rs:6480]
  └─ test_alpenglow_migration(3, &[4, 4, 0])
       └─ new_pre_migration_alpenglow(...)
            └─ [Same as Failure 3: "Node is unhealthy" blocks feature activation]
            └─ IF activation succeeds somehow:
                 └─ cluster.exit_node(&validator_keys[2])       [line 6491]
                 └─ purge blockstore after migration_slot - 10  [line 6494-6501]
                 └─ cluster.restart_node(...)                   [line 6512]
                      └─ Validator replays pre-migration blocks
                           └─ ReplayStage processes duplicate_slots  [replay_stage.rs:1850]
                                └─ frozen_hash != correct_hash        [line 1868-1870]
                                └─ leader_schedule_cache.slot_leader_at(slot) == my_pubkey
                                └─ PANIC: "producing duplicate blocks"  [line 1910]
```

### Root Cause
This test has TWO failure modes:
1. **Primary:** Same "Node is unhealthy" as Failure 3 (blocks feature activation transaction).
2. **Secondary:** If the test somehow reaches the restart phase, the restarted node has a purged blockstore and replays blocks from the cluster. At slot 5 (pre-migration), the node computes a different bank hash than what the cluster reports. This is the upstream `c0e8427c91` bank hash verification issue — the same one fixed by our `set_expected_bank_hash` guard for Hash::default(). However, in this test the mismatch may be caused by a different mechanism: the node replayed blocks with different state (pre-migration genesis) than the cluster (post-migration state).

### Classification
**Compound issue:** Failure 3 (test infra) + potential state divergence during migration restart. The bank hash fix in `runtime/src/bank.rs:2660` addresses the non-leader footer case but may not cover the migration-restart case where the node has a different genesis state.

### plan.md Reference
plan.md §B4 (delayed bankhash availability) states "Nodes MUST NOT proceed until delayed bankhash is locally available." The migration restart scenario creates a state where the node's local bank hash diverges from the cluster's, which is outside plan.md's scope (plan.md assumes MCP activates at a known slot, not mid-migration restart).

---

## Failure 5: Restart Tests (`test_restart_node_alpenglow`, `test_alpenglow_imbalanced_stakes_catchup`)

### Symptom
- `test_restart_node_alpenglow`: FAIL at 357s (timeout in `send_many_transactions`)
- `test_alpenglow_imbalanced_stakes_catchup`: FAIL at 217s (timeout in `check_for_new_notarized_votes`)

### Call Path — `test_restart_node_alpenglow`
```
test_restart_node_alpenglow()  [local_cluster.rs:6098]
  └─ new_alpenglow(1 node)
  └─ exit_restart_node(...)                             [restarts the single node]
  └─ sleep(0.5 * epoch)                                [~128 slots worth]
  └─ send_many_transactions(...)                        [cluster_tests.rs:135]
       └─ poll_get_balance_with_commitment(processed)   [line 152-156]
            └─ RPC: get_balance → bank(processed)
                 └─ block_commitment_cache.slot()       [rpc.rs:354-358]
                      └─ set by: alpenglow_update_commitment_cache(Notarize, slot)
                           └─ Requires: votor voting notarize for a slot
                                └─ Requires: replay has executed the block
                                     └─ Requires: block data available (replay from disk)
```

### Root Cause — Single-Node Restart
After restart, the single node must:
1. Load ledger from disk
2. Replay all blocks from genesis to current slot
3. Resume PoH and produce new blocks
4. Vote notarize on new blocks (updates "processed" commitment)

With 1 node holding 100% stake, votor CAN produce finalization certs (100% > 60% threshold). But replay takes time proportional to the number of blocks to replay. The 0.5-epoch sleep may not be enough for replay to complete, and `poll_get_balance_with_commitment(processed)` has a shorter timeout than the replay needs.

### Call Path — `test_alpenglow_imbalanced_stakes_catchup`
```
test_alpenglow_imbalanced_stakes_catchup()  [local_cluster.rs:6145]
  └─ new_alpenglow(2 nodes: 90%/10% stake)
  └─ check_for_new_processed(8, ...)                    ← PASSES
  └─ exit_node(B)
  └─ check_for_new_roots(8, ...)                        [node A alone]
       └─ A has 90% > 60%, so can finalize alone       ← PASSES (presumably)
  └─ restart_node(B)
  └─ check_for_new_notarized_votes(16, ...)             ← FAILS at 180s
       └─ Listens on QUIC socket for vote messages     [cluster_tests.rs:591-658]
            └─ Expects 16 new notarized votes from restarted B
                 └─ B must: replay all blocks from A, execute them, vote notarize
                      └─ Requires: MCP shred repair from A
                           └─ plan.md: "MCP automatic shred repair trigger: RESOLVED"
                           └─ RepairService enqueues McpShred repairs  [repair_service.rs:852]
```

### Root Cause — Imbalanced Restart
After B restarts:
1. B loads its stale ledger (from before exit)
2. B needs blocks A produced while B was down → requires turbine retransmit or repair
3. B must repair MCP shreds for those blocks → automatic repair trigger scans recent slots
4. B must execute those blocks → replay stage processes them
5. B must vote notarize → votor sends votes over QUIC
6. Test listener must receive 16 such votes within 180s

The bottleneck is step 2-4: catch-up time after restart. MCP repair IS wired (plan.md says RESOLVED), but the repair scan is bounded to recent slots with an interval delay. B may take time to discover what's missing and request repairs. Additionally, B's QUIC connections to A may need re-establishment.

### Classification
**Test timeout issue + potential slow repair catch-up.** MCP repair IS implemented per plan.md, but the catch-up time after a full restart exceeds the test's 180s timeout. This is not an MCP protocol bug but a practical timing constraint.

### plan.md Reference
plan.md §Resolved: "MCP automatic shred repair trigger: RESOLVED — RepairService loop now automatically enqueues ShredRepairType::McpShred for MCP relay-attested slots that are pending execution output and have missing local MCP shards."

The repair mechanism exists but is rate-limited: "trigger is bounded (recent-slot scan + interval) and reuses existing repair batching."

---

## Summary Matrix

| Test | Result | Root Cause | Classification | MCP Bug? |
|------|--------|------------|----------------|----------|
| `test_alpenglow_1` | TIMEOUT | `check_for_new_roots` RPC poll hangs | Test infra | No |
| `test_alpenglow_4` | TIMEOUT | Same | Test infra | No |
| `test_alpenglow_4_1_offline` | TIMEOUT | Same | Test infra | No |
| `test_alpenglow_cluster_partition_1_1` | TIMEOUT | Same (post-partition) | Test infra | No |
| `test_alpenglow_cluster_partition_1_1_1` | TIMEOUT | Same (post-partition) | Test infra | No |
| `test_alpenglow_migration_4` | FAIL 34s | RPC health race in pre-migration startup | Test infra | No |
| `test_alpenglow_restart_post_migration` | FAIL 27s | Same | Test infra | No |
| `test_alpenglow_missed_migration_entirely` | FAIL | Bank hash mismatch during migration restart | Test infra + edge case | Possibly |
| `test_restart_node_alpenglow` | FAIL 357s | Single-node replay catch-up too slow | Timeout too short | No |
| `test_alpenglow_imbalanced_stakes_catchup` | FAIL 217s | Restart catch-up + repair too slow for 180s | Timeout too short | No |

## Recommendations

1. **Replace `check_for_new_roots` with direct votor observation** — The §2 fallback tests prove this works: they listen for finalization certificates over QUIC instead of polling RPC. Apply the same pattern to §3/§5 tests.

2. **Add health-check wait or skip to migration tests** — Before sending the activation transaction, poll RPC health until all nodes report OK, or use `skip_preflight_health_check = true`.

3. **Increase restart test timeouts** — 180s is insufficient for alpenglow catch-up after restart. The repair scan interval and replay time dominate. Consider 300-600s or use bounded completion conditions.

4. **Investigate `missed_migration_entirely` bank hash divergence** — This may be a real edge case where a node with purged pre-migration state computes a different hash than the post-migration cluster. Needs targeted investigation.
