/// contracts/reputation/src/lib.rs
///
/// Agora Reputation Registry — LSSA Smart Contract
///
/// On-chain, immutable reputation scoring for all Agora agents.
///
/// Score model:
///   - 0–10000 scale (0.00%–100.00%)
///   - Initial score: 5000 (50%)
///   - Each trade updates the score using an exponential moving average
///   - Slash events reduce score proportionally
///   - Score is public and cannot be deleted
///
/// Components tracked per agent:
///   - delivery_rate:  fraction of accepted trades delivered on time
///   - latency_score:  normalised actual vs promised latency
///   - price_accuracy: actual price vs quoted price
///   - dispute_rate:   fraction of trades that ended in dispute

use std::collections::BTreeMap;
use agora_common::{
    AgentId, BlockNumber, TimestampMs,
    ContractError, Result, Event,
    MAX_REPUTATION, INITIAL_REPUTATION,
};

// ── State ─────────────────────────────────────────────────────────

/// A single completed trade record, used as input to the reputation calculation.
#[derive(Debug, Clone)]
pub struct TradeAttestation {
    pub escrow_id:          String,
    pub seller_id:          AgentId,
    pub buyer_id:           AgentId,
    pub amount_nom:         u128,
    pub delivered_on_time:  bool,
    pub actual_latency_ms:  u64,
    pub promised_latency_ms: u64,
    pub disputed:           bool,
    pub price_deviation_bps: i32,   // actual - quoted, in basis points
    pub block:              BlockNumber,
    pub ts:                 TimestampMs,
}

/// Per-agent reputation record.
#[derive(Debug, Clone)]
pub struct ReputationRecord {
    pub agent_id:          AgentId,
    pub score:             u32,            // 0–10000, EMA of component scores
    pub delivery_rate:     u32,            // 0–10000
    pub latency_score:     u32,            // 0–10000
    pub price_accuracy:    u32,            // 0–10000
    pub dispute_rate:      u32,            // 0–10000 (lower = better)
    pub total_trades:      u64,
    pub successful_trades: u64,
    pub disputed_trades:   u64,
    pub total_volume_nom:  u128,
    pub last_trade_block:  BlockNumber,
    pub first_trade_block: BlockNumber,
}

impl Default for ReputationRecord {
    fn default() -> Self {
        Self {
            agent_id:          String::new(),
            score:             INITIAL_REPUTATION,
            delivery_rate:     INITIAL_REPUTATION,
            latency_score:     INITIAL_REPUTATION,
            price_accuracy:    INITIAL_REPUTATION,
            dispute_rate:      INITIAL_REPUTATION,
            total_trades:      0,
            successful_trades: 0,
            disputed_trades:   0,
            total_volume_nom:  0,
            last_trade_block:  0,
            first_trade_block: 0,
        }
    }
}

/// Full reputation registry state.
#[derive(Debug, Default)]
pub struct ReputationRegistry {
    sybil_profiles: std::collections::BTreeMap<AgentId, SybilProfile>,
    records:     BTreeMap<AgentId, ReputationRecord>,
    attestations: Vec<TradeAttestation>,
    events:      Vec<Event>,
}

// ── Score calculation ─────────────────────────────────────────────

/// EMA smoothing factor — 20% weight on newest trade, 80% on history.
const EMA_ALPHA_NUM: u32 = 2;
const EMA_ALPHA_DEN: u32 = 11;  // alpha = 2/(10+1) ≈ 18%

/// Component weights: delivery 40%, latency 20%, price 20%, dispute 20%.
const W_DELIVERY:  u32 = 40;
const W_LATENCY:   u32 = 20;
const W_PRICE:     u32 = 20;
const W_DISPUTE:   u32 = 20;

fn ema_update(current: u32, new_value: u32) -> u32 {
    // EMA = alpha * new + (1 - alpha) * current
    let alpha_num = EMA_ALPHA_NUM;
    let alpha_den = EMA_ALPHA_DEN;
    let updated = (alpha_num * new_value + (alpha_den - alpha_num) * current) / alpha_den;
    updated.min(MAX_REPUTATION)
}

fn compute_latency_score(actual_ms: u64, promised_ms: u64) -> u32 {
    if promised_ms == 0 { return INITIAL_REPUTATION; }
    if actual_ms <= promised_ms {
        MAX_REPUTATION  // on-time or early = perfect latency score
    } else {
        // Score degrades linearly: 2x promised = 0 score
        let ratio = actual_ms as f64 / promised_ms as f64;
        let score = (MAX_REPUTATION as f64 * (2.0 - ratio.min(2.0))) as u32;
        score
    }
}

fn compute_price_accuracy(deviation_bps: i32) -> u32 {
    // Perfect score at 0 deviation, degrades linearly to 0 at +/-1000 bps (10%)
    let abs_dev = deviation_bps.unsigned_abs() as u32;
    MAX_REPUTATION.saturating_sub(abs_dev * MAX_REPUTATION / 1000)
}

// ── Contract implementation ───────────────────────────────────────

impl ReputationRegistry {

    /// Record a completed trade and update both agents' reputation scores.
    ///
    /// Called by the escrow contract after each settled trade.
    pub fn record_trade(
        &mut self,
        attestation: TradeAttestation,
    ) -> Result<(u32, u32)> {
        let seller_id = attestation.seller_id.clone();
        let buyer_id  = attestation.buyer_id.clone();
        let block     = attestation.block;

        // Update seller reputation
        let seller_new_score = self.update_seller(&attestation)?;

        // Buyer gets a small reputation boost for completing a trade honestly
        let buyer_new_score = self.update_buyer_participation(&buyer_id, &attestation, block)?;

        self.update_sybil_profile(&seller_id, &buyer_id);
        self.update_sybil_profile(&buyer_id, &seller_id);
        self.attestations.push(attestation);

        self.events.push(Event::ReputationUpdated {
            agent_id: seller_id,
            old_score: 0,   // simplified — production reads before update
            new_score: seller_new_score,
            trade_count: 0,
            block,
        });

        Ok((seller_new_score, buyer_new_score))
    }

    fn update_seller(&mut self, att: &TradeAttestation) -> Result<u32> {
        let record = self.records
            .entry(att.seller_id.clone())
            .or_insert_with(|| ReputationRecord {
                agent_id: att.seller_id.clone(),
                first_trade_block: att.block,
                ..Default::default()
            });

        // Update component scores
        let delivery_score = if att.delivered_on_time { MAX_REPUTATION } else { 0 };
        let latency_score  = compute_latency_score(att.actual_latency_ms, att.promised_latency_ms);
        let price_score    = compute_price_accuracy(att.price_deviation_bps);
        let dispute_score  = if att.disputed { 0 } else { MAX_REPUTATION };

        record.delivery_rate  = ema_update(record.delivery_rate,  delivery_score);
        record.latency_score  = ema_update(record.latency_score,  latency_score);
        record.price_accuracy = ema_update(record.price_accuracy, price_score);
        record.dispute_rate   = ema_update(record.dispute_rate,   dispute_score);

        // Composite weighted score
        let composite = (
            record.delivery_rate  * W_DELIVERY +
            record.latency_score  * W_LATENCY  +
            record.price_accuracy * W_PRICE    +
            record.dispute_rate   * W_DISPUTE
        ) / (W_DELIVERY + W_LATENCY + W_PRICE + W_DISPUTE);

        record.score = composite;
        record.total_trades += 1;
        if att.delivered_on_time && !att.disputed { record.successful_trades += 1; }
        if att.disputed { record.disputed_trades += 1; }
        record.total_volume_nom  = record.total_volume_nom.saturating_add(att.amount_nom);
        record.last_trade_block  = att.block;

        Ok(record.score)
    }

    fn update_buyer_participation(
        &mut self,
        buyer_id: &AgentId,
        att: &TradeAttestation,
        block: BlockNumber,
    ) -> Result<u32> {
        let record = self.records
            .entry(buyer_id.clone())
            .or_insert_with(|| ReputationRecord {
                agent_id: buyer_id.clone(),
                first_trade_block: block,
                ..Default::default()
            });

        // Buyers get dispute_rate penalty if they opened a fraudulent dispute
        if att.disputed {
            record.dispute_rate = ema_update(record.dispute_rate, 0);
        } else {
            record.dispute_rate = ema_update(record.dispute_rate, MAX_REPUTATION);
        }

        // Recompute buyer composite (simpler formula — buyers mostly judged on dispute rate)
        record.score = (record.dispute_rate * 6 + INITIAL_REPUTATION * 4) / 10;
        record.total_trades += 1;
        record.last_trade_block = block;

        Ok(record.score)
    }

    /// Apply a slash to an agent's reputation score.
    ///
    /// Called when the escrow contract slashes a stake (non-delivery or fraud).
    /// Slash reduces score by slash_bps/10000 * current_score.
    pub fn apply_slash(
        &mut self,
        agent_id: &AgentId,
        slash_bps: u32,
        block: BlockNumber,
    ) -> Result<u32> {
        let record = self.records.get_mut(agent_id).ok_or(ContractError::NotRegistered)?;
        let reduction = (record.score as u64 * slash_bps as u64 / 10_000) as u32;
        let old_score = record.score;
        record.score = record.score.saturating_sub(reduction);
        record.delivery_rate = record.delivery_rate.saturating_sub(reduction / 2);

        self.events.push(Event::ReputationUpdated {
            agent_id: agent_id.clone(),
            old_score,
            new_score: record.score,
            trade_count: record.total_trades,
            block,
        });

        Ok(record.score)
    }

    /// Get the current reputation score for an agent (0–10000).
    pub fn score(&self, agent_id: &AgentId) -> u32 {
        self.records.get(agent_id)
            .map(|r| r.score)
            .unwrap_or(INITIAL_REPUTATION)
    }

    /// Get the full reputation record.
    pub fn get(&self, agent_id: &AgentId) -> Option<&ReputationRecord> {
        self.records.get(agent_id)
    }

    /// List agents by minimum score, ordered by score descending.
    pub fn top_agents(&self, min_score: u32, limit: usize) -> Vec<&ReputationRecord> {
        let mut agents: Vec<_> = self.records.values()
            .filter(|r| r.score >= min_score)
            .collect();
        agents.sort_by(|a, b| b.score.cmp(&a.score));
        agents.truncate(limit);
        agents
    }

    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_attestation(delivered: bool, disputed: bool) -> TradeAttestation {
        TradeAttestation {
            escrow_id: "0xescrow001".into(),
            seller_id: "03seller".into(),
            buyer_id:  "02buyer".into(),
            amount_nom: 5_000_000,
            delivered_on_time: delivered,
            actual_latency_ms: 900,
            promised_latency_ms: 1000,
            disputed,
            price_deviation_bps: 0,
            block: 1,
            ts: 1_700_000_000_000,
        }
    }

    #[test]
    fn test_initial_score() {
        let reg = ReputationRegistry::default();
        assert_eq!(reg.score(&"unknown".into()), INITIAL_REPUTATION);
    }

    #[test]
    fn test_score_increases_on_good_trade() {
        let mut reg = ReputationRegistry::default();
        let att = mock_attestation(true, false);
        let (seller_score, _) = reg.record_trade(att).unwrap();
        // Good delivery should push score above initial
        assert!(seller_score >= INITIAL_REPUTATION);
    }

    #[test]
    fn test_score_decreases_on_dispute() {
        let mut reg = ReputationRegistry::default();
        // First establish some reputation
        for _ in 0..5 {
            reg.record_trade(mock_attestation(true, false)).unwrap();
        }
        let before = reg.score(&"03seller".into());
        // Now a dispute
        reg.record_trade(mock_attestation(false, true)).unwrap();
        let after = reg.score(&"03seller".into());
        assert!(after < before, "score should decrease after dispute");
    }

    #[test]
    fn test_slash_reduces_score() {
        let mut reg = ReputationRegistry::default();
        reg.record_trade(mock_attestation(true, false)).unwrap();
        let before = reg.score(&"03seller".into());
        reg.apply_slash(&"03seller".into(), 2000, 2).unwrap(); // 20% slash
        let after = reg.score(&"03seller".into());
        assert!(after < before);
    }

    #[test]
    fn test_top_agents_ordering() {
        let mut reg = ReputationRegistry::default();
        // Create two sellers with different performance
        for _ in 0..10 {
            let mut att = mock_attestation(true, false);
            att.seller_id = "03good".into();
            att.buyer_id  = "02buyer".into();
            reg.record_trade(att).unwrap();
        }
        for _ in 0..3 {
            let mut att = mock_attestation(false, true);
            att.seller_id = "03bad".into();
            att.buyer_id  = "02buyer2".into();
            reg.record_trade(att).unwrap();
        }
        let top = reg.top_agents(0, 10);
        assert!(!top.is_empty());
        // Good seller should rank higher
        if top.len() >= 2 {
            assert!(top[0].score >= top[1].score);
        }
    }
}

// ── Sybil resistance additions (FIX-4) ───────────────────────────

/// Minimum distinct counterparties before a reputation score is considered verified.
pub const MIN_DISTINCT_COUNTERPARTIES: usize = 5;

/// Maximum fraction of trades allowed with the same counterparty (20%).
/// Agents trading >20% of their volume with one partner get a trust penalty.
const MAX_SINGLE_COUNTERPARTY_FRACTION: f64 = 0.20;

/// Trust multiplier applied to unverified agents (< MIN_DISTINCT_COUNTERPARTIES trades).
const UNVERIFIED_TRUST_MULTIPLIER: f64 = 0.5;

#[derive(Debug, Clone, Default)]
pub struct SybilProfile {
    pub distinct_counterparties: std::collections::BTreeSet<String>,
    pub trade_count_per_counterparty: std::collections::BTreeMap<String, u64>,
    pub is_verified: bool,
    pub trust_multiplier: f64,  // 0.0–1.0; applied to displayed reputation
}

impl ReputationRegistry {

    /// Check and update sybil profile for an agent after a trade.
    /// Returns the effective trust multiplier for the agent.
    pub fn update_sybil_profile(
        &mut self,
        agent_id:       &AgentId,
        counterparty:   &AgentId,
    ) -> f64 {
        let profile = self.sybil_profiles
            .entry(agent_id.clone())
            .or_default();

        profile.distinct_counterparties.insert(counterparty.clone());
        *profile.trade_count_per_counterparty
            .entry(counterparty.clone())
            .or_insert(0) += 1;

        // FIX-4: Mark verified only after MIN_DISTINCT_COUNTERPARTIES unique partners
        profile.is_verified =
            profile.distinct_counterparties.len() >= MIN_DISTINCT_COUNTERPARTIES;

        // FIX-4: Check for single-counterparty concentration
        let total_trades: u64 = profile.trade_count_per_counterparty.values().sum();
        let max_concentration = profile.trade_count_per_counterparty.values()
            .map(|&n| n as f64 / total_trades as f64)
            .fold(0.0f64, f64::max);

        profile.trust_multiplier = if !profile.is_verified {
            UNVERIFIED_TRUST_MULTIPLIER
        } else if max_concentration > MAX_SINGLE_COUNTERPARTY_FRACTION {
            // Penalty proportional to how far over the threshold they are
            let excess = max_concentration - MAX_SINGLE_COUNTERPARTY_FRACTION;
            (1.0 - excess * 2.0).max(0.3)
        } else {
            1.0
        };

        profile.trust_multiplier
    }

    /// Get the effective reputation score accounting for sybil penalties.
    /// This is what buyer agents should use — not the raw score.
    pub fn effective_score(&self, agent_id: &AgentId) -> u32 {
        let raw = self.score(agent_id);
        let multiplier = self.sybil_profiles
            .get(agent_id)
            .map(|p| p.trust_multiplier)
            .unwrap_or(UNVERIFIED_TRUST_MULTIPLIER); // new agents start at 50% trust
        (raw as f64 * multiplier) as u32
    }

    /// Get sybil profile for an agent (read-only).
    pub fn sybil_profile(&self, agent_id: &AgentId) -> Option<&SybilProfile> {
        self.sybil_profiles.get(agent_id)
    }
}
