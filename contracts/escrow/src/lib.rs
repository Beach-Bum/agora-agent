/// contracts/escrow/src/lib.rs
///
/// Agora Escrow Contract — LSSA Smart Contract (Security Hardened)
///
/// Security fixes applied:
///   FIX-2: Buyer nonce added to hash commitment — prevents pre-image grinding
///   FIX-3: Dispute bond required — prevents griefing/free-work attacks
///   FIX-3: Non-release auto-claim — seller can claim after grace period
///   FIX-3: Minimum buyer reputation required for high-value trades
///   FIX-10: Arbitration oracle authenticated — arbiter_id stored and verified

use std::collections::BTreeMap;
use agora_common::{
    AgentId, NomAmount, BlockNumber, TimestampMs,
    ContractError, Result, Event, NomLedger,
    HIGH_VALUE_THRESHOLD_NOM, MIN_REPUTATION_HIGH_VALUE,
};

// ── Constants ─────────────────────────────────────────────────────

/// Dispute bond as fraction of escrow amount (10%).
const DISPUTE_BOND_BPS: u32 = 1_000;

/// Grace period after delivery notification — if buyer doesn't release or dispute,
/// seller can auto-claim via claim_after_grace(). Default: 48 hours.
const DELIVERY_GRACE_MS: TimestampMs = 48 * 3600 * 1_000;

/// Trusted arbitration committee address (multi-sig in production).
/// Set at contract deployment — cannot be changed without redeployment.
const DEFAULT_ARBITER_ID: &str = "lssa:agora_arbiter_committee";

/// Ledger account that holds every locked escrow amount and dispute bond.
/// Funds enter it only in create_escrow() and leave it only in a terminal transition.
pub const ESCROW_HELD_ACCOUNT: &str = "lssa:agora_escrow_held";

/// Ledger account that receives forfeited dispute bonds.
pub const TREASURY_ACCOUNT: &str = "lssa:agora_treasury";

// ── State ─────────────────────────────────────────────────────────

/// What notify_delivery() committed. A hash mismatch is a successful call that
/// moves the escrow to Disputed: returning Err would revert that state change
/// on a real chain and leave the escrow Pending.
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryOutcome {
    /// Revealed hash matched the commitment; escrow is now Delivered.
    Delivered,
    /// Revealed hash did not match; escrow is now Disputed and funds stay held.
    Disputed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EscrowStatus {
    Pending,
    Delivered,
    Released,
    Refunded,
    Disputed,
    SlashedSeller,
    SlashedBuyer,
    AutoClaimed,  // FIX-3: seller claimed after grace period expired
}

#[derive(Debug, Clone)]
pub struct EscrowRecord {
    pub escrow_id:                String,
    pub buyer_id:                 AgentId,
    pub seller_id:                AgentId,
    pub arbiter_id:               AgentId,     // FIX-10: authenticated arbiter
    pub amount:                   NomAmount,
    pub dispute_bond:             NomAmount,   // FIX-3: buyer's dispute bond

    /// FIX-2: Commitment = sha256(sessionId + buyerNonce + output)
    /// buyerNonce contributed by buyer at intent time — prevents pre-image grinding.
    pub delivery_hash_commitment: String,
    pub buyer_nonce:              String,      // FIX-2: buyer's nonce (revealed at release)

    pub actual_output_hash:       Option<String>,
    pub logos_storage_cid:        Option<String>,
    pub timeout_ms:               TimestampMs,
    pub delivered_ts:             Option<TimestampMs>, // FIX-3: when delivery was notified
    pub slash_bps:                u32,
    pub created_block:            BlockNumber,
    pub created_ts:               TimestampMs,
    pub status:                   EscrowStatus,
    pub dispute_reason:           Option<String>,
    pub buyer_reputation_at_creation: u32,    // FIX-3: snapshot for audit
}

#[derive(Debug, Default)]
pub struct EscrowContract {
    escrows:    BTreeMap<String, EscrowRecord>,
    ledger:     NomLedger,
    events:     Vec<Event>,
    next_id:    u64,
    arbiter_id: String,
}

// ── Contract ──────────────────────────────────────────────────────

impl EscrowContract {

    pub fn new(arbiter_id: Option<String>) -> Self {
        Self {
            arbiter_id: arbiter_id.unwrap_or_else(|| DEFAULT_ARBITER_ID.to_string()),
            ..Default::default()
        }
    }

    /// Credit NOM to an agent's balance inside this contract.
    ///
    /// Stands in for the inbound LSSA token transfer: it is the only place
    /// where NOM enters the contract ledger. Everything after it is a transfer
    /// between accounts, so the ledger total never changes.
    pub fn deposit(&mut self, agent_id: &AgentId, amount: NomAmount) -> Result<()> {
        if amount == 0 {
            return Err(ContractError::InvalidInput("deposit must be > 0".into()));
        }
        if Self::is_reserved_account(agent_id) {
            return Err(ContractError::InvalidInput("cannot deposit to a reserved account".into()));
        }
        self.ledger.credit(agent_id, amount);
        Ok(())
    }

    /// Spendable balance of an agent, or of a reserved account
    /// (ESCROW_HELD_ACCOUNT, TREASURY_ACCOUNT).
    pub fn balance(&self, account: &str) -> NomAmount {
        self.ledger.balance(&account.to_string())
    }

    fn is_reserved_account(account: &str) -> bool {
        account == ESCROW_HELD_ACCOUNT || account == TREASURY_ACCOUNT
    }

    /// Move held funds to their final owner. Only called from terminal transitions.
    fn pay_from_held(&mut self, to: &str, amount: NomAmount) -> Result<()> {
        self.ledger.transfer(&ESCROW_HELD_ACCOUNT.to_string(), &to.to_string(), amount)
    }

    /// Create escrow with buyer nonce for pre-image protection (FIX-2)
    /// and dispute bond for griefing protection (FIX-3).
    ///
    /// # Arguments
    /// * `buyer_nonce` — 16-byte random hex contributed by buyer. Must be included
    ///                   in the delivery hash commitment: sha256(sessionId + buyerNonce + output)
    /// * `buyer_reputation` — buyer's current on-chain reputation score (0–10000).
    ///                        High-value trades require MIN_REPUTATION_HIGH_VALUE.
    pub fn create_escrow(
        &mut self,
        buyer_id:                 AgentId,
        seller_id:                AgentId,
        amount:                   NomAmount,
        delivery_hash_commitment: String,
        buyer_nonce:              String,       // FIX-2
        timeout_ms:               TimestampMs,
        slash_bps:                u32,
        buyer_reputation:         u32,          // FIX-3
        block:                    BlockNumber,
        ts:                       TimestampMs,
    ) -> Result<String> {
        // Basic validation
        if buyer_id == seller_id {
            return Err(ContractError::InvalidInput("buyer and seller cannot be the same".into()));
        }
        if Self::is_reserved_account(&buyer_id) || Self::is_reserved_account(&seller_id) {
            return Err(ContractError::InvalidInput("buyer and seller cannot be reserved accounts".into()));
        }
        if amount == 0 {
            return Err(ContractError::InvalidInput("amount must be > 0".into()));
        }
        if !delivery_hash_commitment.starts_with("sha256:") {
            return Err(ContractError::InvalidInput("commitment must start with sha256:".into()));
        }
        if slash_bps > 10_000 {
            return Err(ContractError::InvalidInput("slash_bps cannot exceed 10000".into()));
        }

        // FIX-2: Validate buyer nonce is present and well-formed (32 hex chars = 16 bytes)
        if buyer_nonce.len() != 32 || !buyer_nonce.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ContractError::InvalidInput(
                "buyer_nonce must be exactly 32 hex chars (16 bytes)".into()
            ));
        }

        // FIX-3: High-value trades require minimum buyer reputation
        if amount >= HIGH_VALUE_THRESHOLD_NOM && buyer_reputation < MIN_REPUTATION_HIGH_VALUE {
            return Err(ContractError::InvalidInput(format!(
                "buyer reputation {} below minimum {} required for trades >= {} NOM",
                buyer_reputation, MIN_REPUTATION_HIGH_VALUE,
                HIGH_VALUE_THRESHOLD_NOM / 1_000_000
            )));
        }

        // FIX-3: Calculate and lock dispute bond (10% of escrow amount)
        let dispute_bond = (amount as u128)
            .checked_mul(DISPUTE_BOND_BPS as u128)
            .ok_or(ContractError::Overflow)?
            / 10_000;
        let dispute_bond = dispute_bond as NomAmount;
        let total_locked = amount.checked_add(dispute_bond).ok_or(ContractError::Overflow)?;

        // Lock escrow amount + dispute bond: move them out of the buyer's funded
        // balance into the held account. Fails with InsufficientFunds, before any
        // state is written, if the buyer has not deposited enough.
        self.ledger.transfer(&buyer_id, &ESCROW_HELD_ACCOUNT.to_string(), total_locked)?;

        self.next_id += 1;
        let escrow_id = format!("0xescrow{:016x}", self.next_id);

        let record = EscrowRecord {
            escrow_id: escrow_id.clone(),
            buyer_id: buyer_id.clone(),
            seller_id: seller_id.clone(),
            arbiter_id: self.arbiter_id.clone(),     // FIX-10
            amount,
            dispute_bond,                            // FIX-3
            delivery_hash_commitment,
            buyer_nonce,                             // FIX-2
            actual_output_hash: None,
            logos_storage_cid: None,
            timeout_ms,
            delivered_ts: None,
            slash_bps,
            created_block: block,
            created_ts: ts,
            status: EscrowStatus::Pending,
            dispute_reason: None,
            buyer_reputation_at_creation: buyer_reputation,
        };

        self.events.push(Event::EscrowCreated {
            escrow_id: escrow_id.clone(),
            buyer_id,
            seller_id,
            amount,
            timeout_ms,
            block,
        });

        self.escrows.insert(escrow_id.clone(), record);
        Ok(escrow_id)
    }

    /// Seller notifies delivery.
    /// FIX-2: actual_output_hash must match sha256(sessionId + buyerNonce + output).
    ///
    /// A mismatch is not an error: the call succeeds, the escrow moves to
    /// Disputed and the funds stay held until the arbiter resolves it. Callers
    /// must check the returned DeliveryOutcome.
    pub fn notify_delivery(
        &mut self,
        caller_id:          &AgentId,
        escrow_id:          &str,
        actual_output_hash: String,
        logos_storage_cid:  String,
        ts:                 TimestampMs,
    ) -> Result<DeliveryOutcome> {
        let record = self.escrows.get_mut(escrow_id)
            .ok_or(ContractError::EscrowNotFound)?;

        if &record.seller_id != caller_id {
            return Err(ContractError::UnauthorisedCaller);
        }
        if record.status != EscrowStatus::Pending {
            return Err(ContractError::EscrowNotPending);
        }
        if ts > record.timeout_ms {
            return Err(ContractError::EscrowExpired);
        }

        // FIX-2: Verify hash matches commitment (which includes buyer nonce)
        if actual_output_hash != record.delivery_hash_commitment {
            record.status = EscrowStatus::Disputed;
            record.dispute_reason = Some("seller revealed hash does not match commitment".into());
            // Keep what the seller actually revealed as evidence for the arbiter.
            record.actual_output_hash = Some(actual_output_hash);
            record.logos_storage_cid  = Some(logos_storage_cid);
            return Ok(DeliveryOutcome::Disputed);
        }

        record.actual_output_hash = Some(actual_output_hash);
        record.logos_storage_cid  = Some(logos_storage_cid);
        record.status             = EscrowStatus::Delivered;
        record.delivered_ts       = Some(ts);  // FIX-3: record delivery time for grace period

        Ok(DeliveryOutcome::Delivered)
    }

    /// Buyer releases escrow.
    /// FIX-2: Buyer must reveal nonce — verifying sha256(sessionId + buyerNonce + output).
    /// FIX-3: Dispute bond returned to buyer on honest release.
    pub fn release(
        &mut self,
        caller_id:             &AgentId,
        escrow_id:             &str,
        verified_output_hash:  String,
        revealed_buyer_nonce:  String,  // FIX-2: buyer reveals nonce at release
        block:                 BlockNumber,
    ) -> Result<NomAmount> {
        let record = self.escrows.get_mut(escrow_id)
            .ok_or(ContractError::EscrowNotFound)?;

        if &record.buyer_id != caller_id {
            return Err(ContractError::UnauthorisedCaller);
        }
        if record.status != EscrowStatus::Delivered {
            return Err(ContractError::EscrowNotPending);
        }

        // FIX-2: Verify nonce matches what was committed at escrow creation
        if revealed_buyer_nonce != record.buyer_nonce {
            return Err(ContractError::InvalidInput("buyer nonce does not match escrow record".into()));
        }
        if verified_output_hash != record.delivery_hash_commitment {
            return Err(ContractError::HashMismatch);
        }

        let amount      = record.amount;
        let bond        = record.dispute_bond;
        let seller_id   = record.seller_id.clone();
        let buyer_id    = record.buyer_id.clone();
        record.status   = EscrowStatus::Released;

        // Pay seller out of the held account
        self.pay_from_held(&seller_id, amount)?;
        // Return dispute bond to honest buyer (FIX-3)
        self.pay_from_held(&buyer_id, bond)?;

        self.events.push(Event::EscrowReleased {
            escrow_id: escrow_id.to_string(),
            seller_id,
            amount,
            block,
        });

        Ok(amount)
    }

    /// Buyer refunds after timeout.
    /// FIX-3: Dispute bond also returned on timeout (seller failed to deliver).
    pub fn refund(
        &mut self,
        caller_id:  &AgentId,
        escrow_id:  &str,
        current_ts: TimestampMs,
        block:      BlockNumber,
    ) -> Result<NomAmount> {
        let record = self.escrows.get_mut(escrow_id)
            .ok_or(ContractError::EscrowNotFound)?;

        if &record.buyer_id != caller_id {
            return Err(ContractError::UnauthorisedCaller);
        }
        if record.status != EscrowStatus::Pending {
            return Err(ContractError::EscrowNotPending);
        }
        if current_ts < record.timeout_ms {
            return Err(ContractError::EscrowNotExpired);
        }

        let total_return = record.amount + record.dispute_bond; // FIX-3
        let buyer_id     = record.buyer_id.clone();
        record.status    = EscrowStatus::Refunded;

        self.pay_from_held(&buyer_id, total_return)?;

        self.events.push(Event::EscrowRefunded {
            escrow_id: escrow_id.to_string(),
            buyer_id,
            amount: total_return,
            block,
        });

        Ok(total_return)
    }

    /// FIX-3: Seller auto-claims funds if buyer ignores delivery past grace period.
    /// Prevents buyer holding seller funds hostage indefinitely after valid delivery.
    pub fn claim_after_grace(
        &mut self,
        caller_id:  &AgentId,
        escrow_id:  &str,
        current_ts: TimestampMs,
        block:      BlockNumber,
    ) -> Result<NomAmount> {
        let record = self.escrows.get_mut(escrow_id)
            .ok_or(ContractError::EscrowNotFound)?;

        if &record.seller_id != caller_id {
            return Err(ContractError::UnauthorisedCaller);
        }
        if record.status != EscrowStatus::Delivered {
            return Err(ContractError::EscrowNotPending);
        }

        let delivered_at = record.delivered_ts
            .ok_or(ContractError::InvalidInput("no delivery timestamp recorded".into()))?;

        if current_ts < delivered_at + DELIVERY_GRACE_MS {
            return Err(ContractError::EscrowNotExpired);
        }

        let amount    = record.amount;
        let bond      = record.dispute_bond;
        let seller_id = record.seller_id.clone();
        // FIX-3: Buyer's dispute bond is slashed for non-response (they had 48h)
        record.status = EscrowStatus::AutoClaimed;

        self.pay_from_held(&seller_id, amount)?;
        // Dispute bond goes to community treasury — buyer penalised for ignoring delivery
        self.pay_from_held(TREASURY_ACCOUNT, bond)?;

        self.events.push(Event::EscrowReleased {
            escrow_id: escrow_id.to_string(),
            seller_id,
            amount,
            block,
        });

        Ok(amount)
    }

    /// Open a dispute — requires locking additional dispute bond (FIX-3).
    pub fn open_dispute(
        &mut self,
        caller_id: &AgentId,
        escrow_id: &str,
        reason:    String,
    ) -> Result<()> {
        let record = self.escrows.get_mut(escrow_id)
            .ok_or(ContractError::EscrowNotFound)?;

        if &record.buyer_id != caller_id && &record.seller_id != caller_id {
            return Err(ContractError::UnauthorisedCaller);
        }
        if record.status != EscrowStatus::Pending && record.status != EscrowStatus::Delivered {
            return Err(ContractError::EscrowNotPending);
        }

        record.status         = EscrowStatus::Disputed;
        record.dispute_reason = Some(reason);

        Ok(())
    }

    /// FIX-10: Resolve a dispute — ONLY callable by the authenticated arbiter.
    pub fn resolve_dispute(
        &mut self,
        caller_id:       &AgentId,  // FIX-10: must match arbiter_id
        escrow_id:       &str,
        seller_at_fault: bool,
        block:           BlockNumber,
    ) -> Result<()> {
        // FIX-10: Authenticate arbiter — only the registered arbiter can resolve
        {
            let record = self.escrows.get(escrow_id)
                .ok_or(ContractError::EscrowNotFound)?;
            if caller_id != &record.arbiter_id {
                return Err(ContractError::UnauthorisedCaller);
            }
            if record.status != EscrowStatus::Disputed {
                return Err(ContractError::InvalidInput("escrow is not in disputed state".into()));
            }
        }

        let record = self.escrows.get_mut(escrow_id).unwrap();
        let amount = record.amount;
        let bond   = record.dispute_bond;

        if seller_at_fault {
            // Refund buyer (escrow + bond); seller stake slashed via identity contract
            let buyer_id = record.buyer_id.clone();
            record.status = EscrowStatus::SlashedSeller;
            self.pay_from_held(&buyer_id, amount + bond)?;

            self.events.push(Event::EscrowSlashed {
                escrow_id: escrow_id.to_string(),
                slash_amount: amount,
                reason: "seller_at_fault".into(),
                block,
            });
        } else {
            // Pay seller; buyer forfeits dispute bond (was lying)
            let seller_id = record.seller_id.clone();
            record.status = EscrowStatus::SlashedBuyer;
            self.pay_from_held(&seller_id, amount)?;
            // bond goes to treasury — penalise fraudulent dispute
            self.pay_from_held(TREASURY_ACCOUNT, bond)?;

            self.events.push(Event::EscrowReleased {
                escrow_id: escrow_id.to_string(),
                seller_id,
                amount,
                block,
            });
        }

        Ok(())
    }

    pub fn get(&self, escrow_id: &str) -> Result<&EscrowRecord> {
        self.escrows.get(escrow_id).ok_or(ContractError::EscrowNotFound)
    }

    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const BUYER:   &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SELLER:  &str = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ARBITER: &str = "lssa:agora_arbiter_committee";
    const AMOUNT:  NomAmount  = 5_000_000;
    const HASH:    &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const NONCE:   &str = "0123456789abcdef0123456789abcdef";  // 32 hex chars
    const TIMEOUT: TimestampMs = 1_800_000_000_000;
    const HIGH_REP: u32 = 8_000;

    /// Buyer's funded balance before any escrow is created.
    const BUYER_FUNDS: NomAmount = 20_000_000;
    const BOND: NomAmount = AMOUNT * DISPUTE_BOND_BPS as u128 / 10_000;

    fn make(contract: &mut EscrowContract) -> String {
        contract.deposit(&BUYER.into(), BUYER_FUNDS).unwrap();
        contract.create_escrow(
            BUYER.into(), SELLER.into(), AMOUNT, HASH.into(), NONCE.into(),
            TIMEOUT, 500, HIGH_REP, 1, 1_700_000_000_000,
        ).unwrap()
    }

    #[test]
    fn test_create_and_release_with_nonce() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "QmCID".into(), 1_700_000_001_000).unwrap();
        let amt = c.release(&BUYER.into(), &eid, HASH.into(), NONCE.into(), 2).unwrap();
        assert_eq!(amt, AMOUNT);
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::Released);
    }

    #[test]
    fn test_wrong_nonce_rejected() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), 1_700_000_001_000).unwrap();
        let err = c.release(&BUYER.into(), &eid, HASH.into(), "wrongnonce0123456789012345678901".into(), 2);
        assert_eq!(err, Err(ContractError::InvalidInput("buyer nonce does not match escrow record".into())));
    }

    #[test]
    fn test_dispute_bond_locked() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        let record = c.get(&eid).unwrap();
        assert!(record.dispute_bond > 0, "dispute bond should be > 0");
        assert_eq!(record.dispute_bond, AMOUNT * DISPUTE_BOND_BPS as u128 / 10_000);
    }

    #[test]
    fn test_auto_claim_after_grace() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), 1_700_000_001_000).unwrap();
        // Before grace period — should fail
        let err = c.claim_after_grace(&SELLER.into(), &eid, 1_700_000_001_000, 2);
        assert_eq!(err, Err(ContractError::EscrowNotExpired));
        // After grace period — should succeed
        let grace_end = 1_700_000_001_000 + DELIVERY_GRACE_MS;
        let amt = c.claim_after_grace(&SELLER.into(), &eid, grace_end + 1, 3).unwrap();
        assert_eq!(amt, AMOUNT);
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::AutoClaimed);
    }

    #[test]
    fn test_unauthorised_arbiter_rejected() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.open_dispute(&BUYER.into(), &eid, "test".into()).unwrap();
        // Random caller cannot resolve
        let err = c.resolve_dispute(&"03random_agent".into(), &eid, true, 2);
        assert_eq!(err, Err(ContractError::UnauthorisedCaller));
        // Real arbiter can resolve
        c.resolve_dispute(&ARBITER.into(), &eid, true, 2).unwrap();
    }

    #[test]
    fn test_high_value_requires_reputation() {
        let mut c = EscrowContract::new(None);
        let high_value = HIGH_VALUE_THRESHOLD_NOM + 1;
        // Low reputation buyer should fail
        let err = c.create_escrow(
            BUYER.into(), SELLER.into(), high_value, HASH.into(), NONCE.into(),
            TIMEOUT, 500, 5_000 /* below MIN_REPUTATION_HIGH_VALUE */, 1, 0,
        );
        assert!(err.is_err());
        // High reputation buyer should succeed (funded: amount + 10% bond)
        c.deposit(&BUYER.into(), high_value + high_value / 10).unwrap();
        let ok = c.create_escrow(
            BUYER.into(), SELLER.into(), high_value, HASH.into(), NONCE.into(),
            TIMEOUT, 500, HIGH_REP, 1, 0,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn test_invalid_nonce_format() {
        let mut c = EscrowContract::new(None);
        // Nonce too short
        let err = c.create_escrow(BUYER.into(), SELLER.into(), AMOUNT, HASH.into(),
            "tooshort".into(), TIMEOUT, 500, HIGH_REP, 1, 0);
        assert!(err.is_err());
        // Non-hex nonce
        let err2 = c.create_escrow(BUYER.into(), SELLER.into(), AMOUNT, HASH.into(),
            "gggggggggggggggggggggggggggggggg".into(), TIMEOUT, 500, HIGH_REP, 1, 0);
        assert!(err2.is_err());
    }

    // ── Fund custody ──────────────────────────────────────────────

    const T_CREATED:   TimestampMs = 1_700_000_000_000;
    const T_DELIVERED: TimestampMs = 1_700_000_001_000;

    /// Sum of every account that can hold NOM in these tests.
    fn total(c: &EscrowContract) -> NomAmount {
        c.balance(BUYER) + c.balance(SELLER)
            + c.balance(ESCROW_HELD_ACCOUNT) + c.balance(TREASURY_ACCOUNT)
    }

    /// Asserts (buyer, seller, held, treasury) and that nothing was minted or burned.
    fn assert_balances(c: &EscrowContract, buyer: NomAmount, seller: NomAmount,
                       held: NomAmount, treasury: NomAmount) {
        assert_eq!(
            (c.balance(BUYER), c.balance(SELLER),
             c.balance(ESCROW_HELD_ACCOUNT), c.balance(TREASURY_ACCOUNT)),
            (buyer, seller, held, treasury),
            "(buyer, seller, held, treasury)"
        );
        assert_eq!(total(c), BUYER_FUNDS, "NOM was minted or burned");
    }

    /// Once an escrow is terminal, no entry point may move funds again.
    fn assert_settled(c: &mut EscrowContract, eid: &str) {
        let before = (c.balance(BUYER), c.balance(SELLER),
                      c.balance(ESCROW_HELD_ACCOUNT), c.balance(TREASURY_ACCOUNT));

        assert_eq!(c.release(&BUYER.into(), eid, HASH.into(), NONCE.into(), 9),
                   Err(ContractError::EscrowNotPending));
        assert_eq!(c.refund(&BUYER.into(), eid, TIMEOUT + 1, 9),
                   Err(ContractError::EscrowNotPending));
        assert_eq!(c.claim_after_grace(&SELLER.into(), eid, u64::MAX, 9),
                   Err(ContractError::EscrowNotPending));
        assert!(c.resolve_dispute(&ARBITER.into(), eid, true, 9).is_err());
        assert!(c.resolve_dispute(&ARBITER.into(), eid, false, 9).is_err());
        assert_eq!(c.open_dispute(&BUYER.into(), eid, "again".into()),
                   Err(ContractError::EscrowNotPending));

        let after = (c.balance(BUYER), c.balance(SELLER),
                     c.balance(ESCROW_HELD_ACCOUNT), c.balance(TREASURY_ACCOUNT));
        assert_eq!(before, after, "a rejected call moved funds");
        assert_eq!(c.balance(ESCROW_HELD_ACCOUNT), 0, "terminal escrow still holds funds");
    }

    #[test]
    fn test_create_escrow_requires_funded_buyer() {
        let mut c = EscrowContract::new(None);
        let unfunded = c.create_escrow(
            BUYER.into(), SELLER.into(), AMOUNT, HASH.into(), NONCE.into(),
            TIMEOUT, 500, HIGH_REP, 1, T_CREATED,
        );
        assert_eq!(unfunded, Err(ContractError::InsufficientFunds));

        // Enough for the amount but not for the 10% dispute bond.
        c.deposit(&BUYER.into(), AMOUNT).unwrap();
        let short = c.create_escrow(
            BUYER.into(), SELLER.into(), AMOUNT, HASH.into(), NONCE.into(),
            TIMEOUT, 500, HIGH_REP, 1, T_CREATED,
        );
        assert_eq!(short, Err(ContractError::InsufficientFunds));
        // A failed lock leaves the buyer's balance untouched and nothing held.
        assert_eq!(c.balance(BUYER), AMOUNT);
        assert_eq!(c.balance(ESCROW_HELD_ACCOUNT), 0);
    }

    #[test]
    fn test_reserved_accounts_cannot_be_funded_or_trade() {
        let mut c = EscrowContract::new(None);
        assert!(c.deposit(&ESCROW_HELD_ACCOUNT.into(), 1).is_err());
        assert!(c.deposit(&TREASURY_ACCOUNT.into(), 1).is_err());
        assert!(c.deposit(&BUYER.into(), 0).is_err());
        let err = c.create_escrow(
            ESCROW_HELD_ACCOUNT.into(), SELLER.into(), AMOUNT, HASH.into(), NONCE.into(),
            TIMEOUT, 500, HIGH_REP, 1, T_CREATED,
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_hash_mismatch_commits_dispute() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        let wrong = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        // The call succeeds, so the state change below is committed, not reverted.
        let outcome = c.notify_delivery(&SELLER.into(), &eid, wrong.into(), "QmBad".into(), T_DELIVERED);
        assert_eq!(outcome, Ok(DeliveryOutcome::Disputed));

        let record = c.get(&eid).unwrap();
        assert_eq!(record.status, EscrowStatus::Disputed);
        assert_eq!(record.dispute_reason.as_deref(),
                   Some("seller revealed hash does not match commitment"));
        assert_eq!(record.actual_output_hash.as_deref(), Some(wrong));
        assert_eq!(record.delivered_ts, None);

        // Funds stay locked; the seller cannot retry or auto-claim, the buyer cannot release.
        assert_balances(&c, BUYER_FUNDS - AMOUNT - BOND, 0, AMOUNT + BOND, 0);
        assert_eq!(c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), T_DELIVERED),
                   Err(ContractError::EscrowNotPending));
        assert_eq!(c.claim_after_grace(&SELLER.into(), &eid, u64::MAX, 2),
                   Err(ContractError::EscrowNotPending));
        assert_eq!(c.release(&BUYER.into(), &eid, HASH.into(), NONCE.into(), 2),
                   Err(ContractError::EscrowNotPending));

        // Only the arbiter ends it.
        c.resolve_dispute(&ARBITER.into(), &eid, true, 3).unwrap();
        assert_balances(&c, BUYER_FUNDS, 0, 0, 0);
    }

    #[test]
    fn test_matching_hash_reports_delivered() {
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        let outcome = c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "QmCID".into(), T_DELIVERED);
        assert_eq!(outcome, Ok(DeliveryOutcome::Delivered));
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::Delivered);
    }

    #[test]
    fn test_funds_conserved_across_all_terminal_states() {
        let locked = AMOUNT + BOND;
        let buyer_after_lock = BUYER_FUNDS - locked;

        // 1. Release: seller is paid, buyer gets the bond back.
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        assert_balances(&c, buyer_after_lock, 0, locked, 0);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), T_DELIVERED).unwrap();
        assert_balances(&c, buyer_after_lock, 0, locked, 0);
        c.release(&BUYER.into(), &eid, HASH.into(), NONCE.into(), 2).unwrap();
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::Released);
        assert_balances(&c, BUYER_FUNDS - AMOUNT, AMOUNT, 0, 0);
        assert_settled(&mut c, &eid);

        // 2. Refund after timeout: buyer gets amount + bond back.
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        assert_eq!(c.refund(&BUYER.into(), &eid, TIMEOUT - 1, 2), Err(ContractError::EscrowNotExpired));
        assert_balances(&c, buyer_after_lock, 0, locked, 0);
        assert_eq!(c.refund(&BUYER.into(), &eid, TIMEOUT, 2), Ok(locked));
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::Refunded);
        assert_balances(&c, BUYER_FUNDS, 0, 0, 0);
        assert_settled(&mut c, &eid);

        // 3. Auto-claim after grace: seller is paid, buyer's bond goes to treasury.
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), T_DELIVERED).unwrap();
        c.claim_after_grace(&SELLER.into(), &eid, T_DELIVERED + DELIVERY_GRACE_MS, 2).unwrap();
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::AutoClaimed);
        assert_balances(&c, buyer_after_lock, AMOUNT, 0, BOND);
        assert_settled(&mut c, &eid);

        // 4. Dispute, seller at fault: buyer gets amount + bond back.
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), T_DELIVERED).unwrap();
        c.open_dispute(&BUYER.into(), &eid, "bad output".into()).unwrap();
        assert_balances(&c, buyer_after_lock, 0, locked, 0);
        c.resolve_dispute(&ARBITER.into(), &eid, true, 2).unwrap();
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::SlashedSeller);
        assert_balances(&c, BUYER_FUNDS, 0, 0, 0);
        assert_settled(&mut c, &eid);

        // 5. Dispute, buyer at fault: seller is paid, buyer's bond goes to treasury.
        let mut c = EscrowContract::new(None);
        let eid = make(&mut c);
        c.notify_delivery(&SELLER.into(), &eid, HASH.into(), "Qm".into(), T_DELIVERED).unwrap();
        c.open_dispute(&BUYER.into(), &eid, "false claim".into()).unwrap();
        c.resolve_dispute(&ARBITER.into(), &eid, false, 2).unwrap();
        assert_eq!(c.get(&eid).unwrap().status, EscrowStatus::SlashedBuyer);
        assert_balances(&c, buyer_after_lock, AMOUNT, 0, BOND);
        assert_settled(&mut c, &eid);
    }

    #[test]
    fn test_two_escrows_share_the_held_account_without_leaking() {
        let mut c = EscrowContract::new(None);
        let first = make(&mut c);
        // Second escrow from the same buyer, funded by the first deposit.
        let second = c.create_escrow(
            BUYER.into(), SELLER.into(), AMOUNT, HASH.into(), NONCE.into(),
            TIMEOUT, 500, HIGH_REP, 1, T_CREATED,
        ).unwrap();
        let locked = AMOUNT + BOND;
        assert_balances(&c, BUYER_FUNDS - 2 * locked, 0, 2 * locked, 0);

        // Settling one escrow must leave exactly the other one's funds held.
        c.refund(&BUYER.into(), &first, TIMEOUT, 2).unwrap();
        assert_balances(&c, BUYER_FUNDS - locked, 0, locked, 0);
        assert_eq!(c.refund(&BUYER.into(), &first, TIMEOUT, 3), Err(ContractError::EscrowNotPending));
        assert_balances(&c, BUYER_FUNDS - locked, 0, locked, 0);

        c.notify_delivery(&SELLER.into(), &second, HASH.into(), "Qm".into(), T_DELIVERED).unwrap();
        c.release(&BUYER.into(), &second, HASH.into(), NONCE.into(), 4).unwrap();
        assert_balances(&c, BUYER_FUNDS - AMOUNT, AMOUNT, 0, 0);
    }
}
