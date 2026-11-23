"""Admin-only access to the signed audit chain."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.audit_signing import audit_signer
from app.core.database import get_db
from app.core.security import require_admin
from app.models.models import SecureAuditLog
from app.services.audit import verify_audit_chain

router = APIRouter(prefix="/api/audit", tags=["Audit"], dependencies=[Depends(require_admin)])


@router.get("/verify")
def verify(db: Session = Depends(get_db)):
    """Re-verify every chain link and every Ed25519 signature."""
    return verify_audit_chain(db)


@router.get("/public-key")
def public_key():
    """Raw Ed25519 public key (base64) so the chain can be checked outside the app."""
    return {"algorithm": "Ed25519", "public_key": audit_signer.public_key_b64,
            "key_id": audit_signer.key_id}


@router.get("/logs")
def logs(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    rows = db.query(SecureAuditLog).order_by(SecureAuditLog.id.desc()).limit(limit).all()
    return [{"id": r.id, "timestamp": r.timestamp, "payload": r.event_payload,
             "previous_signature": r.previous_hash, "signature": r.cryptographic_hash,
             "signer_key_id": r.signer_key_id} for r in rows]
