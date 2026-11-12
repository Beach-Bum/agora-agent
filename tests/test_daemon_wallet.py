"""
Spending-policy tests for the daemon wallet.

Run from the repo root:
    python -m pytest tests -q
"""

import math

import pytest

from agent.core import daemon_wallet
from agent.core.daemon_wallet import DaemonWallet


@pytest.fixture
def wallet(tmp_path, monkeypatch):
    """A funded wallet whose policy, balance and audit files live in tmp_path."""
    monkeypatch.setattr(daemon_wallet, "DAEMON_WALLET_DIR", tmp_path)
    monkeypatch.setattr(daemon_wallet, "POLICY_FILE", tmp_path / "policy.json")
    monkeypatch.setattr(daemon_wallet, "AUDIT_FILE", tmp_path / "audit.jsonl")
    w = DaemonWallet("test-daemon")
    w.fund(50.0)
    return w


def test_valid_spend_is_approved(wallet):
    assert wallet.check_spend(5.0, "inference") == (True, "approved")
    assert wallet.check_spend(5, "inference") == (True, "approved")


@pytest.mark.parametrize("amount", [
    0, 0.0, -0.0, -1, -5.0, -1e-9,
    math.nan, math.inf, -math.inf,
    True, "5", None,
])
def test_non_positive_and_non_finite_amounts_are_rejected(wallet, amount):
    allowed, reason = wallet.check_spend(amount, "inference")
    assert allowed is False
    assert reason.startswith("invalid amount")


def test_negative_spend_cannot_raise_the_balance(wallet):
    before = wallet.state()["balance_nom"]

    ok, reason = wallet.spend(-25.0, "inference", "edcounterparty", "session-1")
    assert ok is False and reason.startswith("invalid amount")

    ok, reason = wallet.lock_escrow("0xescrow1", -25.0, "inference",
                                    "edcounterparty", "session-1")
    assert ok is False and reason.startswith("invalid amount")

    state = wallet.state()
    assert state["balance_nom"] == before
    assert state["pending_escrows"] == 0
    assert state["spent_today_nom"] == 0


def test_nan_spend_cannot_poison_the_daily_window(wallet):
    ok, _ = wallet.spend(math.nan, "inference", "edcounterparty", "session-1")
    assert ok is False
    # A NaN in the spend window would make every later daily-cap check pass.
    assert wallet.state()["spent_today_nom"] == 0
    assert wallet.check_spend(5.0, "inference") == (True, "approved")


def test_existing_limits_still_apply(wallet):
    assert wallet.check_spend(10.01, "inference")[0] is False      # per-tx limit
    assert wallet.check_spend(50.01, "inference")[0] is False      # balance
    assert wallet.check_spend(5.0, "gambling")[0] is False         # category
