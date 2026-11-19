"""Ed25519 audit-signature demonstration.

This module is NOT an implementation of NIST ML-DSA and does not provide
post-quantum signatures. The ephemeral signing key is generated at process
startup; production use requires a managed, persistent key lifecycle.
"""
import base64
import json

from cryptography.hazmat.primitives.asymmetric import ed25519


class Ed25519AuditSignatureDemo:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.genesis_hash = "SENTINEL_DEMO_GENESIS"

    def sign_incident(self, incident_data: dict, previous_signature: str) -> str:
        payload = json.dumps(incident_data, sort_keys=True) + previous_signature
        signature = self.private_key.sign(payload.encode("utf-8"))
        return base64.b64encode(signature).decode("utf-8")


dsa_engine = Ed25519AuditSignatureDemo()
