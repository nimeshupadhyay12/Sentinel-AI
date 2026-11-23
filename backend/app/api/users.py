"""User administration. Listing is for analysts/admins; changes are admin-only."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import ROLE_ADMIN, get_password_hash, require_admin, require_privileged, utcnow
from app.models.models import RefreshToken, User
from app.schemas.schemas import UserAdminCreate, UserAdminUpdate, UserOut

router = APIRouter(prefix="/api/users", tags=["Users"])


@router.get("/", response_model=list[UserOut])
def get_users(db: Session = Depends(get_db), current_user=Depends(require_privileged)):
    return db.query(User).order_by(User.id).all()


@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(user_in: UserAdminCreate, db: Session = Depends(get_db),
                current_user=Depends(require_admin)):
    """Admin provisioning of an account with an explicit role.

    Unlike public self-registration, an authenticated administrator may be told
    that a username/email is taken: that is not an enumeration risk.
    """
    user = User(username=user_in.username, email=user_in.email,
                hashed_password=get_password_hash(user_in.password), role=user_in.role)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already exists") from None
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, update: UserAdminUpdate, db: Session = Depends(get_db),
                current_user=Depends(require_admin)):
    """Admin-only role change / (de)activation. Role changes and deactivation end all sessions."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    changes = update.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes supplied")
    if user.id == current_user.id and (changes.get("role", ROLE_ADMIN) != ROLE_ADMIN
                                       or changes.get("is_active") is False):
        # Prevent an administrator from locking everyone out by accident.
        raise HTTPException(status_code=400, detail="Administrators cannot demote or deactivate themselves")
    for field, value in changes.items():
        setattr(user, field, value)
    if changes.get("is_active") is False or "role" in changes:
        db.query(RefreshToken).filter(RefreshToken.user_id == user.id,
                                      RefreshToken.revoked_at.is_(None)).update({"revoked_at": utcnow()})
    db.commit()
    db.refresh(user)
    return user
