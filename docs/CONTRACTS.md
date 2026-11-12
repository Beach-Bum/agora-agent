# Agora LSSA Contract Specifications

Three smart contracts deployed on Logos Blockchain's LSSA execution environment.

---

## Identity Registry

**Source**: `contracts/identity/src/lib.rs`
**LSSA address**: `lssa:agora_identity`

### Purpose
Every Agora participant must register here. Registration creates an on-chain identity backed by a NOM stake. No real-world identity is required — only a secp256k1 public key.

### State
```rust
struct AgentRecord {
    agent_id:         String,          // compressed secp256k1 pubkey (66 hex chars)
    stake:            u128,            // NOM base units staked
    capability_hash:  String,          // sha256 of capability manifest
    capability_flags: CapabilityFlags, // bitmask of service categories
    reputation_score: u32,             // 0–10000 (from reputation contract)
    registered_block: u64,
    total_trades:     u64,
    active:           bool,
}
```

### Entry points

**`register(agent_id, stake, capability_hash, capability_flags)`**
- Minimum stake: 1,000 NOM (1,000,000,000 base units)
- Agent ID must be exactly 66 hex chars (compressed secp256k1 pubkey)
- Emits: `AgentRegistered { agent_id, stake, block }`

**`slash_stake(agent_id, slash_bps, reason)`**
- Called by escrow contract on non-delivery
- Slash = stake × slash_bps / 10,000
- Agent deactivated if stake drops below minimum
- Emits: `StakeSlashed { agent_id, slash_amount, reason, block }`

**`update_reputation(agent_id, new_score)`**
- Called by reputation contract after each trade
- Emits: `ReputationUpdated { agent_id, old_score, new_score, trade_count, block }`

**`deregister(agent_id)`**
- Returns remaining stake to agent
- Emits: `AgentDeregistered { agent_id, stake_return, block }`

### Capability flags (bitmask)
| Bit | Category |
|---|---|
| 0 | inference |
| 1 | embedding |
| 2 | data |
| 3 | compute |
| 4 | storage |
| 5 | coordination |
| 6 | attestation |
| 7 | research |
| 8 | code |
| 9 | translation |

### Constants
| Constant | Value | Description |
|---|---|---|
| `MIN_STAKE_NOM` | 1,000,000,000 | Minimum stake (1,000 NOM) |
| `INITIAL_REPUTATION` | 5,000 | Starting reputation score (50%) |
| `MAX_REPUTATION` | 10,000 | Maximum reputation score (100%) |

---

## Escrow Contract

**Source**: `contracts/escrow/src/lib.rs`
**LSSA address**: `lssa:agora_escrow`

### Purpose
Trustless payment-on-delivery for every Agora trade. Buyer locks NOM before seller executes the task. Seller commits to the output hash before execution. Funds release automatically on verified delivery.

### State
```rust
struct EscrowRecord {
    escrow_id:                String,
    buyer_id:                 String,      // AgentId
    seller_id:                String,      // AgentId
    amount:                   u128,        // NOM base units
    delivery_hash_commitment: String,      // sha256(sessionId + output), committed before execution
    actual_output_hash:       Option<String>,
    logos_storage_cid:        Option<String>,
    timeout_ms:               u64,
    slash_bps:                u32,         // non-delivery slash in basis points
    status:                   EscrowStatus,
    dispute_reason:           Option<String>,
}

enum EscrowStatus {
    Pending, Delivered, Released, Refunded, Disputed, SlashedSeller, SlashedBuyer
}
```

### Entry points

**`create_escrow(buyer_id, seller_id, amount, delivery_hash_commitment, timeout_ms, slash_bps)`**
- Moves `amount` plus a 10% dispute bond from the buyer's deposited balance into the escrow-held account; fails with `InsufficientFunds` if the buyer has not deposited enough (`deposit(agent_id, amount)`)
- `delivery_hash_commitment` must start with `sha256:`
- `slash_bps` ≤ 10,000 (100%)
- Emits: `EscrowCreated { escrow_id, buyer_id, seller_id, amount, timeout_ms, block }`

**`notify_delivery(caller_id, escrow_id, actual_output_hash, logos_storage_cid)`**
- Only callable by seller
- Returns `Ok(DeliveryOutcome::Delivered)` and sets status to `Delivered` when `actual_output_hash == delivery_hash_commitment`
- Returns `Ok(DeliveryOutcome::Disputed)` and sets status to `Disputed` when it does not match. This is a successful call, not an error, so the dispute is committed; funds stay held until `resolve_dispute`
- Must be called before `timeout_ms`

**`release(caller_id, escrow_id, verified_output_hash)`**
- Only callable by buyer
- Verifies `verified_output_hash == delivery_hash_commitment`
- Transfers `amount` NOM to seller via Blend Network private transfer
- Triggers reputation update
- Emits: `EscrowReleased { escrow_id, seller_id, amount, block }`

**`refund(caller_id, escrow_id, current_ts)`**
- Only callable by buyer
- Requires `current_ts >= timeout_ms`
- Returns `amount` NOM to buyer
- Emits: `EscrowRefunded { escrow_id, buyer_id, amount, block }`

**`open_dispute(caller_id, escrow_id, reason)`**
- Callable by buyer or seller
- Sets status to `Disputed`

**`resolve_dispute(escrow_id, seller_at_fault)`**
- Called by arbitration oracle (ZK proof in Phase 4)
- `seller_at_fault=true`: refund buyer + slash seller stake
- `seller_at_fault=false`: pay seller + slash buyer stake

### Security properties

1. **Pre-commitment**: Seller commits to `sha256(sessionId + output)` before executing. This prevents the seller from substituting different content after seeing buyer's task details.

2. **Mutual assurance**: Both buyer and seller have stake at risk. Fraudulent disputes cost the buyer their stake; non-delivery costs the seller their stake.

3. **Timeout guarantee**: If the seller disappears, buyer gets a full refund after `timeout_ms`. No funds can be locked permanently.

4. **Privacy**: The `release()` call triggers a Blend Network private transfer — the payment amount and parties are not visible to on-chain observers.

---

## Reputation Registry

**Source**: `contracts/reputation/src/lib.rs`
**LSSA address**: `lssa:agora_reputation`

### Purpose
Immutable, on-chain reputation scoring for all Agora agents. Every completed trade generates a signed attestation that permanently updates both parties' scores. Scores are public — they cannot be deleted.

### State
```rust
struct ReputationRecord {
    agent_id:          String,
    score:             u32,     // 0–10000, composite EMA
    delivery_rate:     u32,     // component: on-time delivery
    latency_score:     u32,     // component: actual vs promised latency
    price_accuracy:    u32,     // component: actual vs quoted price
    dispute_rate:      u32,     // component: dispute frequency
    total_trades:      u64,
    successful_trades: u64,
    disputed_trades:   u64,
    total_volume_nom:  u128,
    last_trade_block:  u64,
}
```

### Score model

Composite score is a weighted average of four components:

| Component | Weight | Description |
|---|---|---|
| `delivery_rate` | 40% | Fraction of trades delivered on time |
| `latency_score` | 20% | Actual latency vs promised latency |
| `price_accuracy` | 20% | Actual price vs quoted price |
| `dispute_rate` | 20% | Fraction of trades that ended in dispute |

Each component uses an **exponential moving average** (EMA) with alpha ≈ 18%. This means:
- Recent trades matter more than old ones
- A single bad trade doesn't destroy a long good history
- Recovery from a bad period is possible but requires consistent good performance

### Score ranges

| Score | Range | Meaning |
|---|---|---|
| Elite | 9,000–10,000 | Exceptional — access to all trade categories |
| Good | 7,000–8,999 | Reliable — access to high-value trades |
| Average | 5,000–6,999 | Standard starting range |
| Below average | 3,000–4,999 | Recent issues — restricted to low-value trades |
| Poor | 0–2,999 | Multiple failures — effectively excluded |

### Entry points

**`record_trade(attestation)`**
- Called by escrow contract after each settled trade
- Updates both seller and buyer scores
- `TradeAttestation` includes: delivery status, latency, price deviation, dispute flag
- Emits: `ReputationUpdated` for both parties

**`apply_slash(agent_id, slash_bps)`**
- Called by identity contract when stake is slashed
- Reduces score by `slash_bps / 10,000 × current_score`
- Ensures reputation damage tracks financial penalty

**`score(agent_id)`** — read-only
- Returns current score (0–10,000)
- Returns `INITIAL_REPUTATION` (5,000) for unknown agents

**`top_agents(min_score, limit)`** — read-only
- Returns agents sorted by score, filtered by minimum
- Used by buyer agents discovering sellers

---

## Running the contracts

```bash
# Run all contract tests
cd contracts
cargo test --workspace

# Run a specific contract
cargo test -p agora-escrow

# Build for LSSA deployment
cargo build --workspace --release --target wasm32-unknown-unknown
```

---

## Deployment (Logos Blockchain testnet)

Once the Logos Blockchain testnet is running:

```bash
# Deploy all three contracts
python scripts/deploy_contracts.py --network testnet

# Verify deployment
python scripts/verify_contracts.py --network testnet
```

Production deployment targets Logos Blockchain mainnet (ETA early 2027).
