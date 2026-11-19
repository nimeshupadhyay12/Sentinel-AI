"""AES-GCM telemetry demonstration.

This module is intentionally NOT an implementation of NIST ML-KEM.
It uses one random, process-local demonstration key so the encrypt/decrypt
round trip can be exercised within this running process. It must not be used
as a production key-establishment protocol.
"""
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AesGcmTelemetryDemo:
    def __init__(self):
        # Process-local demonstration key; generated at startup and not persisted.
        self._demo_key = os.urandom(32)

    def encapsulate_telemetry(self, telemetry_data: dict) -> dict:
        payload_bytes = json.dumps(telemetry_data).encode("utf-8")
        aesgcm = AESGCM(self._demo_key)
        nonce = os.urandom(12)
        encrypted_payload = aesgcm.encrypt(nonce, payload_bytes, None)
        return {
            "crypto_demo": "AES-256-GCM (not ML-KEM)",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "cipher_text": base64.b64encode(encrypted_payload).decode("utf-8"),
        }

    def decapsulate_telemetry(self, encrypted_package: dict) -> dict:
        nonce = base64.b64decode(encrypted_package["nonce"])
        cipher_text = base64.b64decode(encrypted_package["cipher_text"])
        aesgcm = AESGCM(self._demo_key)
        decrypted_bytes = aesgcm.decrypt(nonce, cipher_text, None)
        return json.loads(decrypted_bytes.decode("utf-8"))


# Kept as a module-level instance for the existing activity route demonstration.
pqc_engine = AesGcmTelemetryDemo()
