"""
Message authentication tests.

Run from the repo root:
    python -m pytest tests -q
"""

import hashlib
import hmac
import json
import secrets
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.core import signing
from agent.logos.messaging import (
    BuyIntent,
    CapabilityManifest,
    CapabilityService,
    DeliveryNotification,
    NonceCache,
    Offer,
    RATE_LIMIT_PER_SENDER_PER_MIN,
    RateLimiter,
    canonical_bytes,
    sign_message,
    validate_incoming_message,
    verify_message,
)


class Agent:
    """A keypair: 32 private bytes and the agent id derived from them."""

    def __init__(self):
        self.private_key = secrets.token_bytes(32)
        self.agent_id = signing.agent_id_from_private_key(self.private_key)

    def sign(self, data: bytes) -> str:
        return signing.sign(self.private_key, data)


def over_the_wire(msg: dict) -> dict:
    """What the receiver sees: the message after a JSON encode/decode."""
    return json.loads(json.dumps(msg))


def buy_intent(buyer: Agent, signer: Agent = None, nonce: str = None) -> dict:
    """A buy_intent claiming to be from `buyer`, signed by `signer` (default: buyer)."""
    msg = {
        "version": "agora/1",
        "type": "buy_intent",
        "buyerId": buyer.agent_id,
        "category": "inference",
        "budget": "5",
        "ts": int(time.time() * 1000),
        "nonce": nonce or secrets.token_hex(16),
    }
    return over_the_wire(sign_message(msg, (signer or buyer).sign))


@pytest.fixture
def alice():
    return Agent()


@pytest.fixture
def mallory():
    return Agent()


@pytest.fixture
def guards():
    return NonceCache(), RateLimiter()


# ── Identity ──────────────────────────────────────────────────────

def test_agent_id_is_the_public_key(alice):
    assert len(alice.agent_id) == 66
    assert alice.agent_id.startswith("ed")
    # Verify with the library directly, using nothing but the agent id.
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(alice.agent_id[2:]))
    public.verify(bytes.fromhex(alice.sign(b"hello")), b"hello")  # raises if invalid


def test_verify_rejects_malformed_input(alice):
    sig = alice.sign(b"hello")
    assert signing.verify(alice.agent_id, b"hello", sig)
    assert not signing.verify(alice.agent_id, b"hellO", sig)
    assert not signing.verify(alice.agent_id, b"hello", sig[:-2])
    assert not signing.verify(alice.agent_id, b"hello", "zz" * 64)
    assert not signing.verify("03" + alice.agent_id[2:], b"hello", sig)
    assert not signing.verify(alice.agent_id[:-2], b"hello", sig)
    assert not signing.verify(None, b"hello", sig)
    assert not signing.verify(alice.agent_id, b"hello", None)


# ── Valid messages ────────────────────────────────────────────────

def test_valid_message_passes(alice, guards):
    msg = buy_intent(alice)
    assert verify_message(msg) == (True, "ok")
    assert validate_incoming_message(msg, *guards) == (True, "ok")


def test_every_marketplace_message_type_verifies(alice, mallory, guards):
    bob = mallory  # just a second honest party here
    messages = [
        CapabilityManifest(
            agent_id=alice.agent_id, identity_tx_hash="0xabc", stake="1000",
            reputation=0.94,
            capabilities=[CapabilityService(id="inference-v1", category="inference",
                                            price_per_unit="0.001")],
        ).to_message(alice.sign),
        BuyIntent(
            buyer_id=alice.agent_id, category="inference", budget="5",
            max_price_per_unit="0.01", max_latency_ms=10_000, min_reputation=0.7,
            expire_ts=int(time.time() * 1000) + 60_000,
        ).to_message(alice.sign),
        # An offer names both parties; it is the seller who signs it.
        Offer(
            session_id="s1", seller_id=bob.agent_id, buyer_id=alice.agent_id,
            capability_id="inference-v1", price_per_unit="0.001", estimated_units=2000,
            total_price="2.0", delivery_timeout_ms=30_000,
            delivery_hash_commitment="sha256:" + "ab" * 32,
        ).to_message(bob.sign),
        DeliveryNotification(
            session_id="s1", escrow_id="0xescrow1", seller_id=bob.agent_id,
            cid="QmCID", output_hash="sha256:" + "ab" * 32,
        ).to_message(bob.sign),
    ]
    for msg in messages:
        received = over_the_wire(msg)
        assert validate_incoming_message(received, *guards) == (True, "ok"), msg["type"]


# ── Tampering ─────────────────────────────────────────────────────

@pytest.mark.parametrize("field, value", [
    ("budget", "5000"),
    ("category", "compute"),
    ("ts", None),          # replaced below with a shifted timestamp
    ("nonce", "f" * 32),
])
def test_tampered_field_is_rejected(alice, guards, field, value):
    msg = buy_intent(alice)
    msg[field] = msg["ts"] + 1 if field == "ts" else value

    valid, reason = validate_incoming_message(msg, *guards)
    assert not valid
    assert reason.startswith("invalid signature")


def test_added_field_is_rejected(alice, guards):
    msg = buy_intent(alice)
    msg["escrowParams"] = {"slashBps": 10_000}
    valid, reason = validate_incoming_message(msg, *guards)
    assert not valid and reason.startswith("invalid signature")


# ── Replay ────────────────────────────────────────────────────────

def test_replayed_nonce_is_rejected(alice, guards):
    msg = buy_intent(alice)
    assert validate_incoming_message(msg, *guards) == (True, "ok")
    assert validate_incoming_message(dict(msg), *guards) == (
        False, "replay attack: nonce already seen")


# ── Forgery ───────────────────────────────────────────────────────

def test_forged_sender_is_rejected(alice, mallory, guards):
    # Mallory signs with her own key but claims to be Alice.
    forged = buy_intent(buyer=alice, signer=mallory)
    assert forged["buyerId"] == alice.agent_id

    valid, reason = validate_incoming_message(forged, *guards)
    assert not valid
    assert reason.startswith("invalid signature")
    assert verify_message(forged)[0] is False


def test_offer_signed_by_the_buyer_is_rejected(alice, mallory, guards):
    # Alice (buyer) tries to mint an offer in the seller's name.
    seller = mallory
    offer = Offer(
        session_id="s1", seller_id=seller.agent_id, buyer_id=alice.agent_id,
        capability_id="inference-v1", price_per_unit="0", estimated_units=1,
        total_price="0", delivery_timeout_ms=30_000,
        delivery_hash_commitment="sha256:" + "ab" * 32,
    ).to_message(alice.sign)
    valid, reason = validate_incoming_message(over_the_wire(offer), *guards)
    assert not valid and reason.startswith("invalid signature")


def test_forged_message_does_not_burn_the_nonce(alice, mallory, guards):
    # Mallory sees Alice's nonce and races a forgery that reuses it.
    nonce = secrets.token_hex(16)
    forged = buy_intent(buyer=alice, signer=mallory, nonce=nonce)
    genuine = buy_intent(buyer=alice, nonce=nonce)

    assert validate_incoming_message(forged, *guards)[0] is False
    # The genuine message with that nonce is still accepted afterwards.
    assert validate_incoming_message(genuine, *guards) == (True, "ok")


def test_forged_messages_do_not_use_up_the_senders_rate_limit(alice, mallory, guards):
    for _ in range(RATE_LIMIT_PER_SENDER_PER_MIN * 3):
        forged = buy_intent(buyer=alice, signer=mallory)
        assert validate_incoming_message(forged, *guards)[0] is False
    assert validate_incoming_message(buy_intent(alice), *guards) == (True, "ok")


def test_unsigned_marketplace_message_is_rejected(alice, guards):
    msg = buy_intent(alice)
    del msg["sig"]
    assert validate_incoming_message(msg, *guards) == (False, "missing signature")


def test_old_hmac_pseudo_signature_is_rejected(alice, guards):
    # The scheme this replaced: HMAC keyed with the private key, dressed up as DER.
    msg = buy_intent(alice)
    msg["sig"] = "3045" + hmac.new(alice.private_key, canonical_bytes(msg),
                                   hashlib.sha256).hexdigest()
    valid, reason = validate_incoming_message(msg, *guards)
    assert not valid and reason.startswith("invalid signature")


# ── Malformed input ───────────────────────────────────────────────

@pytest.mark.parametrize("bad_ts", ["1742000000000", None, 1.5, True])
def test_non_integer_timestamp_is_rejected(alice, guards, bad_ts):
    msg = buy_intent(alice)
    msg["ts"] = bad_ts
    assert validate_incoming_message(msg, *guards) == (
        False, "ts must be an integer (unix ms)")


def test_non_object_message_is_rejected(guards):
    assert validate_incoming_message(["not", "a", "dict"], *guards)[0] is False
