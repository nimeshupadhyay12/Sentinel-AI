"""AES-256-GCM telemetry encryption demonstration (classical, not post-quantum).

Earlier versions of this file were named ``pqc_kem.py``. It is NOT an
implementation of NIST ML-KEM or any key-encapsulation mechanism: it uses one
random, process-local symmetric key so an encrypt/decrypt round trip can be
shown. It is not used by the API and must not be used as a production
key-establishment or data-protection scheme.
"""
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AesGcmTelemetryDemo:
    def __init__(self):
        # Process-local demonstration key; generated at startup and not persisted.
        self._demo_key = os.urandom(32)

    def encrypt(self, telemetry_data: dict) -> dict:
        payload_bytes = json.dumps(telemetry_data).encode("utf-8")
        nonce = os.urandom(12)
        encrypted_payload = AESGCM(self._demo_key).encrypt(nonce, payload_bytes, None)
        return {
            "crypto_demo": "AES-256-GCM (classical; not ML-KEM, not post-quantum)",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "cipher_text": base64.b64encode(encrypted_payload).decode("utf-8"),
        }

    def decrypt(self, encrypted_package: dict) -> dict:
        nonce = base64.b64decode(encrypted_package["nonce"])
        cipher_text = base64.b64decode(encrypted_package["cipher_text"])
        decrypted_bytes = AESGCM(self._demo_key).decrypt(nonce, cipher_text, None)
        return json.loads(decrypted_bytes.decode("utf-8"))
