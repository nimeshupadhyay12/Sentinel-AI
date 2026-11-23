"""Append-only, Ed25519-signed audit chain for detector/response decisions.

``append_audit_record`` links each new record to the previous one;
``verify_audit_chain`` re-checks every link AND every signature.

What verification proves: no stored record was edited, inserted, deleted or
reordered after it was written, unless the attacker also holds the signing key.
What it cannot prove on its own: that the newest records were not truncated
from the end. To cover that, record ``head_signature`` and ``records`` from the
verify response somewhere the database admin cannot write (a ticket, a WORM
bucket) and compare later.
"""
import threading

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.audit_signing import GENESIS, AuditSigner, audit_signer
from app.models.models import SecureAuditLog

# One writer at a time, so two concurrent requests cannot both link to the same
# previous record and fork the chain. The thread lock covers one process; the
# PostgreSQL advisory lock (held until commit) covers several workers.
append_lock = threading.Lock()
_PG_AUDIT_LOCK_ID = 72819347


def append_audit_record(db: Session, payload: dict, signer: AuditSigner = audit_signer) -> SecureAuditLog:
    """Add a signed record to the session. Call under ``append_lock`` and commit before releasing it."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _PG_AUDIT_LOCK_ID})
    last = db.query(SecureAuditLog).order_by(SecureAuditLog.id.desc()).first()
    previous = last.cryptographic_hash if last else GENESIS
    record = SecureAuditLog(event_payload=payload, previous_hash=previous,
                            cryptographic_hash=signer.sign(payload, previous),
                            signer_key_id=signer.key_id)
    db.add(record)
    return record


def verify_audit_chain(db: Session, signer: AuditSigner = audit_signer) -> dict:
    """Walk the whole chain in insertion order, checking links and signatures.

    Status values:
      VERIFIED            every link and every signature is valid
      PARTIALLY_VERIFIED  no tampering found, but some legacy records were signed
                          with a key that was never stored (older versions made a
                          new random key on every start)
      COMPROMISED         a broken link or an invalid signature was found
      EMPTY               no records yet
    """
    logs = db.query(SecureAuditLog).order_by(SecureAuditLog.id.asc()).all()
    base = {"public_key": signer.public_key_b64, "key_id": signer.key_id, "records": len(logs)}
    if not logs:
        return {**base, "status": "EMPTY", "is_valid": True, "verified": 0, "unverifiable": 0,
                "head_signature": None, "message": "No audit records found."}

    verified = unverifiable = 0
    expected_previous = GENESIS

    def failure(log, reason, message):
        return {**base, "status": "COMPROMISED", "is_valid": False, "tampered_at_id": log.id,
                "reason": reason, "verified": verified, "unverifiable": unverifiable,
                "message": message}

    for log in logs:
        if log.previous_hash != expected_previous:
            return failure(log, "broken_link",
                           f"Record #{log.id} does not link to the record before it "
                           "(a record was deleted, inserted or reordered).")
        if log.signer_key_id is None:
            unverifiable += 1
        elif log.signer_key_id != signer.key_id:
            return failure(log, "unknown_signing_key",
                           f"Record #{log.id} names signing key {log.signer_key_id}, "
                           "which is not the configured audit key.")
        elif not signer.verify(log.event_payload, log.previous_hash, log.cryptographic_hash):
            return failure(log, "bad_signature",
                           f"Record #{log.id} has an invalid Ed25519 signature "
                           "(its payload or signature was modified).")
        else:
            verified += 1
        expected_previous = log.cryptographic_hash

    status = "VERIFIED" if unverifiable == 0 else "PARTIALLY_VERIFIED"
    message = ("All links and signatures verified." if status == "VERIFIED" else
               f"Links intact; {unverifiable} legacy record(s) predate persistent signing keys, "
               "so their signatures cannot be checked.")
    return {**base, "status": status, "is_valid": True, "verified": verified,
            "unverifiable": unverifiable, "head_signature": logs[-1].cryptographic_hash,
            "message": message}
