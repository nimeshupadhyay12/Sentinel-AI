"""Tamper-evidence of the Ed25519-signed audit chain and its admin endpoint."""
import base64

import pytest

from app.core.audit_signing import GENESIS, AuditSigner
from app.core.database import SessionLocal
from app.models.models import SecureAuditLog
from app.services.audit import append_audit_record, verify_audit_chain


@pytest.fixture
def chain(client):
    """An isolated chain: snapshot existing rows, start empty, restore afterwards.

    Depends on ``client`` so the app's startup migration has created the tables.
    """
    with SessionLocal() as db:
        saved = [dict(id=r.id, timestamp=r.timestamp, event_payload=r.event_payload,
                      cryptographic_hash=r.cryptographic_hash, previous_hash=r.previous_hash,
                      signer_key_id=r.signer_key_id) for r in db.query(SecureAuditLog).all()]
        db.query(SecureAuditLog).delete()
        db.commit()
    signer = AuditSigner(seed=b'\x01' * 32)
    yield signer
    with SessionLocal() as db:
        db.query(SecureAuditLog).delete()
        db.add_all(SecureAuditLog(**row) for row in saved)
        db.commit()


def _write(signer, n=4):
    with SessionLocal() as db:
        for i in range(n):
            append_audit_record(db, {'user_id': i, 'risk_score': 10.5 * i, 'game_action': 'MONITOR'}, signer)
            db.commit()
        return [r.id for r in db.query(SecureAuditLog).order_by(SecureAuditLog.id).all()]


def test_signature_round_trip_and_rejects_modification():
    signer = AuditSigner(seed=b'\x02' * 32)
    payload = {'b': 1, 'a': 2.5}
    signature = signer.sign(payload, GENESIS)
    assert signer.verify({'a': 2.5, 'b': 1}, GENESIS, signature)  # key order irrelevant
    assert not signer.verify({'a': 2.5, 'b': 2}, GENESIS, signature)
    assert not signer.verify(payload, 'other-previous', signature)
    assert not signer.verify(payload, GENESIS, 'not-base64!!')
    assert not AuditSigner(seed=b'\x03' * 32).verify(payload, GENESIS, signature)


def test_intact_chain_verifies_every_signature(chain):
    _write(chain)
    with SessionLocal() as db:
        result = verify_audit_chain(db, chain)
    assert result['status'] == 'VERIFIED' and result['is_valid']
    assert result['verified'] == result['records'] == 4


def test_edited_payload_is_detected_by_signature(chain):
    ids = _write(chain)
    with SessionLocal() as db:
        row = db.get(SecureAuditLog, ids[2])
        row.event_payload = dict(row.event_payload, risk_score=0.0)  # hide a high score
        db.commit()
        result = verify_audit_chain(db, chain)
    # The links are untouched, so only signature checking can catch this.
    assert result['status'] == 'COMPROMISED' and result['reason'] == 'bad_signature'
    assert result['tampered_at_id'] == ids[2]


def test_deleted_record_is_detected_by_broken_link(chain):
    ids = _write(chain)
    with SessionLocal() as db:
        db.delete(db.get(SecureAuditLog, ids[1]))
        db.commit()
        result = verify_audit_chain(db, chain)
    assert result['status'] == 'COMPROMISED' and result['reason'] == 'broken_link'
    assert result['tampered_at_id'] == ids[2]


def test_forged_signature_from_another_key_is_detected(chain):
    ids = _write(chain, 2)
    attacker = AuditSigner(seed=b'\x09' * 32)
    with SessionLocal() as db:
        row = db.get(SecureAuditLog, ids[1])
        row.event_payload = {'user_id': 1, 'risk_score': 0.0, 'game_action': 'ALLOW'}
        row.cryptographic_hash = attacker.sign(row.event_payload, row.previous_hash)
        db.commit()
        claims_our_key = verify_audit_chain(db, chain)
        row.signer_key_id = attacker.key_id
        db.commit()
        claims_other_key = verify_audit_chain(db, chain)
    assert claims_our_key['reason'] == 'bad_signature'
    assert claims_other_key['reason'] == 'unknown_signing_key'


def test_legacy_unkeyed_records_are_reported_not_hidden(chain):
    _write(chain, 2)
    with SessionLocal() as db:
        first = db.query(SecureAuditLog).order_by(SecureAuditLog.id).first()
        first.signer_key_id = None  # as written by the old ephemeral-key version
        db.commit()
        result = verify_audit_chain(db, chain)
    assert result['status'] == 'PARTIALLY_VERIFIED' and result['unverifiable'] == 1


def test_verify_endpoint_is_admin_only_and_checks_live_chain(client, admin_headers, analyst_headers, user_headers):
    vector = dict(login_hour=3., files_accessed=60., sensitive_files_accessed=9., bytes_transferred_mb=900.,
                  failed_logins=2., privilege_level=2., session_duration_min=400.)
    assert client.post('/api/activities/analyze', json=vector, headers=analyst_headers).status_code == 200
    for headers in (analyst_headers, user_headers):
        assert client.get('/api/audit/verify', headers=headers).status_code == 403
    assert client.get('/api/audit/verify').status_code == 401
    result = client.get('/api/audit/verify', headers=admin_headers).json()
    assert result['status'] == 'VERIFIED' and result['verified'] >= 1
    key = client.get('/api/audit/public-key', headers=admin_headers).json()
    assert len(base64.b64decode(key['public_key'])) == 32 and key['key_id'] == result['key_id']
    logs = client.get('/api/audit/logs?limit=1', headers=admin_headers).json()
    assert logs[0]['payload']['risk_score'] >= 0 and logs[0]['signer_key_id'] == key['key_id']
