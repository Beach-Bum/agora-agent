"""
agent/core/signing.py

Ed25519 identities and signatures for Agora agents.

An agent id IS the agent's public key: the byte 0xed (the multicodec code for
an Ed25519 public key) followed by the 32-byte raw key, hex-encoded. That is
66 hex characters, the length the identity contract expects. Anyone holding a
message and its sender's agent id can check the signature; no shared secret
and no lookup are involved.

The 32 bytes kept in the keystore are used as the Ed25519 seed.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AGENT_ID_PREFIX = "ed"      # multicodec 0xed = ed25519-pub
AGENT_ID_HEX_LEN = 66       # 1 prefix byte + 32 key bytes
SIGNATURE_HEX_LEN = 128     # 64-byte Ed25519 signature


def agent_id_from_private_key(private_key: bytes) -> str:
    """Derive the public agent id from a 32-byte private seed."""
    public = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return AGENT_ID_PREFIX + raw.hex()


def sign(private_key: bytes, data: bytes) -> str:
    """Sign data with a 32-byte private seed. Returns the signature as hex."""
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(data).hex()


def verify(agent_id: str, data: bytes, signature_hex: str) -> bool:
    """
    True only if signature_hex is a valid Ed25519 signature over data by the
    key that agent_id encodes. Malformed input of any kind returns False.
    """
    if not isinstance(agent_id, str) or not isinstance(signature_hex, str):
        return False
    if len(agent_id) != AGENT_ID_HEX_LEN or not agent_id.startswith(AGENT_ID_PREFIX):
        return False
    if len(signature_hex) != SIGNATURE_HEX_LEN:
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(agent_id[2:]))
        public.verify(bytes.fromhex(signature_hex), data)
    except (ValueError, InvalidSignature):
        return False
    return True
