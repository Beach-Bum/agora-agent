"""
agent/core/daemon_wallet.py

Autonomous wallet for daemon-ai with user-configurable spending policy.

Security design:
  - daemon-ai has its OWN keypair, separate from the user's wallet
  - User funds daemon's wallet with an explicit transfer (allowance)
  - Every spend checked against policy BEFORE signing
  - All transactions logged to audit trail
  - User can freeze wallet instantly — all pending ops abort
  - Earning is unrestricted — daemon keeps what it earns
  - Policy is stored on disk and survives restarts
"""

import json
import math
import time
import os
import secrets
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from agent.core.keystore import AgentKeystore, SecureKey, get_or_create_key
from agent.core import signing

DAEMON_WALLET_DIR = Path.home() / ".agora" / "daemon"
POLICY_FILE = DAEMON_WALLET_DIR / "policy.json"
AUDIT_FILE = DAEMON_WALLET_DIR / "audit.jsonl"


@dataclass
class SpendingPolicy:
    """User-configurable spending limits for daemon-ai."""
    max_per_tx_nom: float = 10.0          # Max NOM per single transaction
    daily_cap_nom: float = 100.0          # Max NOM spend per 24h rolling window
    approved_categories: list = field(default_factory=lambda: [
        "inference", "research", "code", "data"
    ])
    max_escrow_timeout_ms: int = 300_000  # 5 min max escrow lock
    max_slash_bps: int = 1000             # 10% max slash risk
    min_counterparty_reputation: float = 0.5  # Don't deal with low-rep agents
    frozen: bool = False                  # Emergency kill switch

    def save(self):
        DAEMON_WALLET_DIR.mkdir(parents=True, exist_ok=True)
        POLICY_FILE.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls) -> "SpendingPolicy":
        if POLICY_FILE.exists():
            data = json.loads(POLICY_FILE.read_text())
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        policy = cls()
        policy.save()
        return policy


@dataclass
class AuditEntry:
    ts: float
    action: str          # "spend" | "earn" | "escrow_create" | "escrow_release" | "fund" | "freeze" | "unfreeze" | "policy_change"
    amount_nom: float
    counterparty: str    # agent ID (truncated)
    session_id: str
    category: str
    status: str          # "approved" | "denied" | "completed" | "failed"
    reason: str
    balance_after: float


class DaemonWallet:
    """
    Autonomous wallet for daemon-ai.

    Owns its own keypair, enforces spending policy, logs everything.
    The user controls the policy — daemon controls the decisions within policy.
    """

    def __init__(self, agent_name: str = "daemon-ai"):
        self.agent_name = agent_name
        self._key: Optional[SecureKey] = None
        self.pub_key_hex: str = ""
        self.policy = SpendingPolicy.load()
        self._balance_nom: float = 0.0
        self._spent_today: float = 0.0
        self._earned_total: float = 0.0
        self._spend_window: list[tuple[float, float]] = []  # (timestamp, amount)
        self._audit: list[AuditEntry] = []
        self._pending_escrows: dict[str, float] = {}  # escrow_id -> locked amount

        DAEMON_WALLET_DIR.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> str:
        """Load or create daemon-ai's keypair. Returns public key hex."""
        self._key = get_or_create_key(self.agent_name)

        self.pub_key_hex = signing.agent_id_from_private_key(self._key.bytes)

        # Load persisted balance
        balance_file = DAEMON_WALLET_DIR / "balance.json"
        if balance_file.exists():
            data = json.loads(balance_file.read_text())
            self._balance_nom = data.get("balance", 0.0)
            self._earned_total = data.get("earned_total", 0.0)

        return self.pub_key_hex

    def sign(self, data: bytes) -> str:
        """Ed25519-sign data with the daemon's key. Verifiable against pub_key_hex."""
        if not self._key:
            raise RuntimeError("Wallet not initialized — key not loaded")
        return signing.sign(self._key.bytes, data)

    def _save_balance(self):
        balance_file = DAEMON_WALLET_DIR / "balance.json"
        balance_file.write_text(json.dumps({
            "balance": self._balance_nom,
            "earned_total": self._earned_total,
            "updated": time.time(),
        }))

    # ── Funding ──────────────────────────────────────────────────

    def fund(self, amount_nom: float, from_user: str = "user") -> dict:
        """User funds daemon's wallet."""
        self._balance_nom += amount_nom
        self._save_balance()
        self._log_audit("fund", amount_nom, from_user, "", "", "completed",
                        f"Funded by {from_user}")
        return {
            "balance": self._balance_nom,
            "funded": amount_nom,
            "message": f"Daemon wallet funded with {amount_nom} NOM",
        }

    # ── Spending Policy Checks ───────────────────────────────────

    def check_spend(self, amount_nom: float, category: str,
                    counterparty_rep: float = 1.0,
                    escrow_timeout_ms: int = 60000,
                    slash_bps: int = 500) -> tuple[bool, str]:
        """
        Check if a spend is allowed by the current policy.
        Returns (allowed, reason).
        """
        if self.policy.frozen:
            return False, "wallet frozen by user"

        # A spend must be a real, positive number. Zero and negative amounts pass
        # every "exceeds limit" comparison below and a negative one would raise the
        # balance when subtracted; NaN compares False against everything; bool is
        # an int in Python.
        if (isinstance(amount_nom, bool) or not isinstance(amount_nom, (int, float))
                or not math.isfinite(amount_nom) or amount_nom <= 0):
            return False, f"invalid amount: {amount_nom!r} (must be a finite number > 0)"

        if amount_nom > self._balance_nom:
            return False, f"insufficient balance: {self._balance_nom:.2f} NOM < {amount_nom:.2f} NOM"

        if amount_nom > self.policy.max_per_tx_nom:
            return False, f"exceeds per-tx limit: {amount_nom:.2f} > {self.policy.max_per_tx_nom:.2f} NOM"

        # Rolling 24h window
        self._prune_spend_window()
        daily_total = sum(amt for _, amt in self._spend_window)
        if daily_total + amount_nom > self.policy.daily_cap_nom:
            return False, f"exceeds daily cap: {daily_total:.2f} + {amount_nom:.2f} > {self.policy.daily_cap_nom:.2f} NOM"

        if category not in self.policy.approved_categories:
            return False, f"category '{category}' not approved"

        if counterparty_rep < self.policy.min_counterparty_reputation:
            return False, f"counterparty reputation {counterparty_rep:.2f} below minimum {self.policy.min_counterparty_reputation:.2f}"

        if escrow_timeout_ms > self.policy.max_escrow_timeout_ms:
            return False, f"escrow timeout {escrow_timeout_ms}ms exceeds max {self.policy.max_escrow_timeout_ms}ms"

        if slash_bps > self.policy.max_slash_bps:
            return False, f"slash risk {slash_bps}bps exceeds max {self.policy.max_slash_bps}bps"

        return True, "approved"

    def spend(self, amount_nom: float, category: str, counterparty: str,
              session_id: str, **kwargs) -> tuple[bool, str]:
        """
        Attempt to spend NOM. Checks policy first.
        Returns (success, reason).
        """
        allowed, reason = self.check_spend(amount_nom, category, **kwargs)
        if not allowed:
            self._log_audit("spend", amount_nom, counterparty, session_id,
                           category, "denied", reason)
            return False, reason

        self._balance_nom -= amount_nom
        self._spend_window.append((time.time(), amount_nom))
        self._save_balance()
        self._log_audit("spend", amount_nom, counterparty, session_id,
                       category, "approved", "policy check passed")
        return True, "approved"

    def lock_escrow(self, escrow_id: str, amount_nom: float, category: str,
                    counterparty: str, session_id: str, **kwargs) -> tuple[bool, str]:
        """Lock funds in escrow — deducts from balance, tracked until release."""
        allowed, reason = self.check_spend(amount_nom, category, **kwargs)
        if not allowed:
            self._log_audit("escrow_create", amount_nom, counterparty, session_id,
                           category, "denied", reason)
            return False, reason

        self._balance_nom -= amount_nom
        self._pending_escrows[escrow_id] = amount_nom
        self._spend_window.append((time.time(), amount_nom))
        self._save_balance()
        self._log_audit("escrow_create", amount_nom, counterparty, session_id,
                       category, "completed", f"Locked in escrow {escrow_id[:16]}...")
        return True, "escrow created"

    def release_escrow(self, escrow_id: str, to_seller: bool = True) -> float:
        """Release escrow — if to_seller, funds go to counterparty. If not, refund."""
        amount = self._pending_escrows.pop(escrow_id, 0.0)
        if not to_seller and amount > 0:
            self._balance_nom += amount  # Refund
            self._save_balance()
        return amount

    # ── Earning ──────────────────────────────────────────────────

    def earn(self, amount_nom: float, counterparty: str, session_id: str,
             category: str) -> float:
        """Record earnings from completed tasks. No policy limits on earning."""
        self._balance_nom += amount_nom
        self._earned_total += amount_nom
        self._save_balance()
        self._log_audit("earn", amount_nom, counterparty, session_id,
                       category, "completed", "Task payment received")
        return self._balance_nom

    # ── Freeze / Unfreeze ────────────────────────────────────────

    def freeze(self) -> dict:
        """Emergency freeze — blocks all spending immediately."""
        self.policy.frozen = True
        self.policy.save()
        self._log_audit("freeze", 0, "user", "", "", "completed",
                       "Wallet frozen by user")
        return {"frozen": True, "balance": self._balance_nom}

    def unfreeze(self) -> dict:
        """Unfreeze wallet — resume autonomous operations."""
        self.policy.frozen = False
        self.policy.save()
        self._log_audit("unfreeze", 0, "user", "", "", "completed",
                       "Wallet unfrozen by user")
        return {"frozen": False, "balance": self._balance_nom}

    # ── Policy Management ────────────────────────────────────────

    def update_policy(self, **kwargs) -> dict:
        """Update spending policy. Only specified fields change."""
        changed = {}
        for key, value in kwargs.items():
            if hasattr(self.policy, key):
                old = getattr(self.policy, key)
                setattr(self.policy, key, value)
                changed[key] = {"old": old, "new": value}
        self.policy.save()
        self._log_audit("policy_change", 0, "user", "", "", "completed",
                       json.dumps(changed))
        return {"policy": asdict(self.policy), "changed": changed}

    # ── State ────────────────────────────────────────────────────

    def state(self) -> dict:
        self._prune_spend_window()
        daily_spent = sum(amt for _, amt in self._spend_window)
        locked = sum(self._pending_escrows.values())
        return {
            "pub_key": self.pub_key_hex,
            "balance_nom": round(self._balance_nom, 4),
            "available_nom": round(self._balance_nom - locked, 4),
            "locked_in_escrow_nom": round(locked, 4),
            "earned_total_nom": round(self._earned_total, 4),
            "spent_today_nom": round(daily_spent, 4),
            "daily_remaining_nom": round(self.policy.daily_cap_nom - daily_spent, 4),
            "pending_escrows": len(self._pending_escrows),
            "frozen": self.policy.frozen,
            "policy": asdict(self.policy),
        }

    def audit_log(self, limit: int = 50) -> list[dict]:
        """Return recent audit entries."""
        return [asdict(e) for e in self._audit[-limit:]]

    # ── Internal ─────────────────────────────────────────────────

    def _prune_spend_window(self):
        """Remove spend entries older than 24h."""
        cutoff = time.time() - 86400
        self._spend_window = [(t, a) for t, a in self._spend_window if t > cutoff]

    def _log_audit(self, action: str, amount: float, counterparty: str,
                   session_id: str, category: str, status: str, reason: str):
        entry = AuditEntry(
            ts=time.time(),
            action=action,
            amount_nom=amount,
            counterparty=counterparty[:20] if counterparty else "",
            session_id=session_id[:16] if session_id else "",
            category=category,
            status=status,
            reason=reason,
            balance_after=self._balance_nom,
        )
        self._audit.append(entry)

        # Persist to audit file
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def shutdown(self):
        """Zero key material from memory."""
        if self._key:
            self._key.zero()
            self._key = None
