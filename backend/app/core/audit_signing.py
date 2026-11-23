"""Ed25519 signatures for the tamper-evident audit chain.

Classical cryptography: Ed25519 is NOT post-quantum and this is not NIST
ML-DSA. (Earlier versions of this file were misleadingly named ``pqc_dsa.py``.)

Each audit record stores ``signature = Ed25519(canonical_json(payload) ||
previous_signature)``. Because every signature covers the previous one, the
records form a hash-chain-like structure: editing a payload breaks that
record's signature, and deleting or reordering records breaks the link of the
next record.

Key management: the signing key comes from ``AUDIT_SIGNING_KEY`` (base64 of a
32-byte Ed25519 seed) or, when unset, is derived from ``SECRET_KEY`` with HKDF
so signatures stay verifiable across restarts. A production deployment should
keep the key in a KMS/HSM and publish the public key out of band.
"""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

GENESIS = "SENTINEL_DEMO_GENESIS"


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load_seed() -> bytes:
    if settings.AUDIT_SIGNING_KEY:
        seed = base64.b64decode(settings.AUDIT_SIGNING_KEY, validate=True)
        if len(seed) != 32:
            raise ValueError("AUDIT_SIGNING_KEY must be base64 of exactly 32 bytes")
        return seed
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sentinel-ai-audit-v1",
                info=b"ed25519-audit-signing-key").derive(settings.SECRET_KEY.encode("utf-8"))


class AuditSigner:
    def __init__(self, seed: bytes | None = None):
        self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed or _load_seed())
        self.public_key = self.private_key.public_key()
        raw = self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_b64 = base64.b64encode(raw).decode("ascii")
        # Short fingerprint stored with each record so a key change is reported
        # as "signed by a different key" instead of as a forged signature.
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]
        self.genesis_hash = GENESIS

    @staticmethod
    def _message(payload: dict, previous_signature: str) -> bytes:
        return (canonical_json(payload) + previous_signature).encode("utf-8")

    def sign(self, payload: dict, previous_signature: str) -> str:
        signature = self.private_key.sign(self._message(payload, previous_signature))
        return base64.b64encode(signature).decode("ascii")

    def verify(self, payload: dict, previous_signature: str, signature_b64: str) -> bool:
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            self.public_key.verify(signature, self._message(payload, previous_signature))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


audit_signer = AuditSigner()
