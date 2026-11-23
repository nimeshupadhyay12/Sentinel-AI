from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, is_privileged, require_privileged
from app.models.models import ActivityLog, User
from app.schemas.schemas import ActivityCreate, ActivityOut, TelemetryVector
from app.services.orchestrator import orchestrator

router = APIRouter(prefix="/api/activities", tags=["Activities"])


@router.post("/log")
def log_activity(activity_in: ActivityCreate, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    """Record one event for the calling account and score it.

    The feature vector is built only from what was submitted plus the real
    server-side hour; nothing is inferred from unrelated fields.
    """
    db.add(ActivityLog(
        user_id=current_user.id,
        action_type=activity_in.action_type,
        bytes_transferred=activity_in.bytes_transferred,
        is_sensitive_file=activity_in.is_sensitive_file,
        failed_attempts=activity_in.failed_attempts,
        privilege_level=activity_in.privilege_level,
        session_duration_sec=activity_in.session_duration_sec,
    ))
    now = datetime.now(timezone.utc)
    raw_telemetry = {
        "login_hour": round(now.hour + now.minute / 60.0, 2),
        "files_accessed": 1.0 if activity_in.action_type in ("FILE_ACCESS", "FILE_READ") else 0.0,
        "sensitive_files_accessed": 1.0 if activity_in.is_sensitive_file else 0.0,
        "bytes_transferred_mb": float(activity_in.bytes_transferred),
        "failed_logins": float(activity_in.failed_attempts),
        "privilege_level": float(activity_in.privilege_level),
        "session_duration_min": float(activity_in.session_duration_sec / 60.0),
    }
    analysis = orchestrator.analyze_event(current_user.id, raw_telemetry, db)
    return {"message": "Activity analyzed", "assessment": analysis}


@router.get("/recent", response_model=list[ActivityOut])
def get_recent_activities(limit: int = Query(25, ge=1, le=200), db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_user)):
    """Analysts and admins see all telemetry; a standard user only sees their own."""
    query = db.query(ActivityLog)
    if not is_privileged(current_user):
        query = query.filter(ActivityLog.user_id == current_user.id)
    return query.order_by(ActivityLog.timestamp.desc(), ActivityLog.id.desc()).limit(limit).all()


@router.post("/analyze")
def analyze_telemetry(payload: TelemetryVector,
                      user_id: int | None = Query(None, ge=1, le=2147483647,
                                                  description="Subject user (defaults to the caller)"),
                      db: Session = Depends(get_db), current_user: User = Depends(require_privileged)):
    """Analyze an exact session/user-day vector supplied by an analyst."""
    subject_id = user_id or current_user.id
    if db.get(User, subject_id) is None:
        raise HTTPException(status_code=404, detail="Target user does not exist")
    sample = payload.model_dump()
    db.add(ActivityLog(user_id=subject_id, action_type="MANUAL_TELEMETRY",
                       bytes_transferred=sample['bytes_transferred_mb'],
                       is_sensitive_file=sample['sensitive_files_accessed'] > 0,
                       failed_attempts=int(sample['failed_logins']),
                       privilege_level=int(sample['privilege_level']),
                       session_duration_sec=sample['session_duration_min'] * 60))
    return {"message": "Telemetry analyzed", "assessment": orchestrator.analyze_event(subject_id, sample, db)}
