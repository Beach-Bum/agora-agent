/// contracts/identity/src/lib.rs
///
/// Agora Identity Registry — LSSA Smart Contract
///
/// Every agent that participates in the marketplace must register here.
/// Registration mints an on-chain identity NFT backed by a NOM stake.
///
/// Properties:
///   - No real-world identity required — just a secp256k1 public key
///   - Stake = credibility bond. Non-delivery slashes the stake.
///   - Agents can hold multiple identities (different roles/personas)
///   - Deregistering returns stake minus any pending slash deductions
///
/// LSSA deployment note:
///   This contract is deployed as a Sovereign Zone program on Logos Blockchain.
///   State lives in LSSA public state (identity registry is public by design).
///   NOM transfers use LSSA private state for amount privacy.

use std::collections::BTreeMap;
use agora_common::{
    AgentId, NomAmount, BlockNumber, TimestampMs,
    ContractError, Result, Event, MIN_STAKE_NOM, INITIAL_REPUTATION,
};

// ── State ─────────────────────────────────────────────────────────

/// Capability category bitmask — agents declare what they can sell.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapabilityFlags {
    pub inference:    bool,
    pub embedding:    bool,
    pub data:         bool,
    pub compute:      bool,
    pub storage:      bool,
    pub coordination: bool,
    pub attestation:  bool,
    pub research:     bool,
    pub code:         bool,
    pub translation:  bool,
}

impl CapabilityFlags {
    pub fn as_u16(&self) -> u16 {
        let mut bits: u16 = 0;
        if self.inference    { bits |= 1 << 0; }
        if self.embedding    { bits |= 1 << 1; }
        if self.data         { bits |= 1 << 2; }
        if self.compute      { bits |= 1 << 3; }
        if self.storage      { bits |= 1 << 4; }
        if self.coordination { bits |= 1 << 5; }
        if self.attestation  { bits |= 1 << 6; }
        if self.research     { bits |= 1 << 7; }
        if self.code         { bits |= 1 << 8; }
        if self.translation  { bits |= 1 << 9; }
        bits
    }

    pub fn from_u16(bits: u16) -> Self {
        Self {
            inference:    bits & (1 << 0) != 0,
            embedding:    bits & (1 << 1) != 0,
            data:         bits & (1 << 2) != 0,
            compute:      bits & (1 << 3) != 0,
            storage:      bits & (1 << 4) != 0,
            coordination: bits & (1 << 5) != 0,
            attestation:  bits & (1 << 6) != 0,
            research:     bits & (1 << 7) != 0,
            code:         bits & (1 << 8) != 0,
            translation:  bits & (1 << 9) != 0,
        }
    }
}

/// On-chain record for a registered agent.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRecord {
    pub agent_id:          AgentId,
    pub stake:             NomAmount,
    pub capability_hash:   String,         // sha256 of capability manifest
    pub capability_flags:  CapabilityFlags,
    pub reputation_score:  u32,            // 0–10000 (from reputation contract)
    pub registered_block:  BlockNumber,
    pub registered_ts:     TimestampMs,
    pub last_active_block: BlockNumber,
    pub total_trades:      u64,
    pub active:            bool,
}

/// Full identity registry state.
#[derive(Debug, Default)]
pub struct IdentityRegistry {
    agents: BTreeMap<AgentId, AgentRecord>,
    events: Vec<Event>,
}

// ── Contract implementation ───────────────────────────────────────

impl IdentityRegistry {

    /// Register a new agent identity.
    ///
    /// # Arguments
    /// * `agent_id`          — compressed secp256k1 public key hex (66 chars)
    /// * `stake`             — NOM amount to stake (must be >= MIN_STAKE_NOM)
    /// * `capability_hash`   — sha256 of the agent's capability manifest
    /// * `capability_flags`  — declared service categories
    /// * `block`             — current block number (set by LSSA runtime)
    /// * `ts`                — current timestamp ms (set by LSSA runtime)
    pub fn register(
        &mut self,
        agent_id: AgentId,
        stake: NomAmount,
        capability_hash: String,
        capability_flags: CapabilityFlags,
        block: BlockNumber,
        ts: TimestampMs,
    ) -> Result<&AgentRecord> {
        // Validate inputs
        if agent_id.len() != 66 {
            return Err(ContractError::InvalidInput(
                "agent_id must be 66-char compressed secp256k1 pubkey hex".into()
            ));
        }
        if self.agents.contains_key(&agent_id) {
            return Err(ContractError::AlreadyRegistered);
        }
        if stake < MIN_STAKE_NOM {
            return Err(ContractError::InsufficientStake);
        }

        let record = AgentRecord {
            agent_id:          agent_id.clone(),
            stake,
            capability_hash,
            capability_flags,
            reputation_score:  INITIAL_REPUTATION,
            registered_block:  block,
            registered_ts:     ts,
            last_active_block: block,
            total_trades:      0,
            active:            true,
        };

        self.events.push(Event::AgentRegistered {
            agent_id: agent_id.clone(),
            stake,
            block,
        });

        self.agents.insert(agent_id.clone(), record);
        Ok(self.agents.get(&agent_id).unwrap())
    }

    /// Look up an agent's record.
    pub fn get(&self, agent_id: &AgentId) -> Result<&AgentRecord> {
        self.agents.get(agent_id).ok_or(ContractError::NotRegistered)
    }

    /// Check if an agent is registered and active.
    pub fn is_active(&self, agent_id: &AgentId) -> bool {
        self.agents.get(agent_id).map(|r| r.active).unwrap_or(false)
    }

    /// Update reputation score (called by reputation contract after each trade).
    pub fn update_reputation(
        &mut self,
        agent_id: &AgentId,
        new_score: u32,
        block: BlockNumber,
    ) -> Result<()> {
        let record = self.agents.get_mut(agent_id).ok_or(ContractError::NotRegistered)?;
        let old_score = record.reputation_score;
        record.reputation_score = new_score;
        record.last_active_block = block;
        record.total_trades += 1;

        self.events.push(Event::ReputationUpdated {
            agent_id: agent_id.clone(),
            old_score,
            new_score,
            trade_count: record.total_trades,
            block,
        });
        Ok(())
    }

    /// Slash an agent's stake (called by escrow contract on non-delivery).
    ///
    /// Slash amount = stake * slash_bps / 10000.
    /// Slashed NOM goes to a community treasury (address set at deployment).
    pub fn slash_stake(
        &mut self,
        agent_id: &AgentId,
        slash_bps: u32,    // basis points, e.g. 500 = 5%
        reason: String,
        block: BlockNumber,
    ) -> Result<NomAmount> {
        let record = self.agents.get_mut(agent_id).ok_or(ContractError::NotRegistered)?;

        let slash_amount = (record.stake as u128)
            .checked_mul(slash_bps as u128)
            .ok_or(ContractError::Overflow)?
            / 10_000;
        let slash_amount = slash_amount as NomAmount;

        record.stake = record.stake.saturating_sub(slash_amount);

        // Deactivate if stake drops below minimum
        if record.stake < MIN_STAKE_NOM {
            record.active = false;
        }

        self.events.push(Event::StakeSlashed {
            agent_id: agent_id.clone(),
            slash_amount,
            reason,
            block,
        });

        Ok(slash_amount)
    }

    /// Deregister an agent and return their stake (minus any slashes).
    pub fn deregister(
        &mut self,
        agent_id: &AgentId,
        block: BlockNumber,
    ) -> Result<NomAmount> {
        let record = self.agents.get_mut(agent_id).ok_or(ContractError::NotRegistered)?;
        let stake_return = record.stake;
        record.active = false;
        record.stake = 0;

        self.events.push(Event::AgentDeregistered {
            agent_id: agent_id.clone(),
            stake_return,
            block,
        });

        Ok(stake_return)
    }

    /// Return all active agents with a given capability flag.
    pub fn list_by_capability(&self, flags: &CapabilityFlags) -> Vec<&AgentRecord> {
        let query = flags.as_u16();
        self.agents.values()
            .filter(|r| r.active && (r.capability_flags.as_u16() & query) != 0)
            .collect()
    }

    /// Drain emitted events (called by LSSA runtime to write to event log).
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Total registered agents (active + inactive).
    pub fn total_agents(&self) -> usize {
        self.agents.len()
    }

    /// Active agents count.
    pub fn active_agents(&self) -> usize {
        self.agents.values().filter(|r| r.active).count()
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_agent_id() -> AgentId {
        "03".to_string() + &"a".repeat(64)  // 66-char mock pubkey
    }

    #[test]
    fn test_register_success() {
        let mut registry = IdentityRegistry::default();
        let agent_id = mock_agent_id();
        let result = registry.register(
            agent_id.clone(),
            MIN_STAKE_NOM,
            "sha256:abc123".into(),
            CapabilityFlags { inference: true, ..Default::default() },
            1000,
            1_700_000_000_000,
        );
        assert!(result.is_ok());
        assert!(registry.is_active(&agent_id));
        assert_eq!(registry.active_agents(), 1);
    }

    #[test]
    fn test_register_duplicate_fails() {
        let mut registry = IdentityRegistry::default();
        let agent_id = mock_agent_id();
        registry.register(agent_id.clone(), MIN_STAKE_NOM, "hash".into(), Default::default(), 1, 0).unwrap();
        let result = registry.register(agent_id, MIN_STAKE_NOM, "hash".into(), Default::default(), 2, 0);
        assert_eq!(result, Err(ContractError::AlreadyRegistered));
    }

    #[test]
    fn test_register_insufficient_stake() {
        let mut registry = IdentityRegistry::default();
        let result = registry.register(mock_agent_id(), MIN_STAKE_NOM - 1, "hash".into(), Default::default(), 1, 0);
        assert_eq!(result, Err(ContractError::InsufficientStake));
    }

    #[test]
    fn test_slash_deactivates_below_minimum() {
        let mut registry = IdentityRegistry::default();
        let agent_id = mock_agent_id();
        registry.register(agent_id.clone(), MIN_STAKE_NOM, "hash".into(), Default::default(), 1, 0).unwrap();
        // Slash 100% — should deactivate
        registry.slash_stake(&agent_id, 10_000, "test".into(), 2).unwrap();
        assert!(!registry.is_active(&agent_id));
    }

    #[test]
    fn test_list_by_capability() {
        let mut registry = IdentityRegistry::default();
        let id1 = "03".to_string() + &"b".repeat(64);
        let id2 = "03".to_string() + &"c".repeat(64);
        registry.register(id1, MIN_STAKE_NOM, "h".into(), CapabilityFlags { inference: true, ..Default::default() }, 1, 0).unwrap();
        registry.register(id2, MIN_STAKE_NOM, "h".into(), CapabilityFlags { data: true, ..Default::default() }, 1, 0).unwrap();
        let inference_agents = registry.list_by_capability(&CapabilityFlags { inference: true, ..Default::default() });
        assert_eq!(inference_agents.len(), 1);
    }

    #[test]
    fn test_events_emitted() {
        let mut registry = IdentityRegistry::default();
        registry.register(mock_agent_id(), MIN_STAKE_NOM, "hash".into(), Default::default(), 1, 0).unwrap();
        let events = registry.drain_events();
        assert_eq!(events.len(), 1);
        matches!(events[0], Event::AgentRegistered { .. });
    }
}
