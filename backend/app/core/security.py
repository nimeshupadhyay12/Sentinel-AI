"""Password hashing, JWT access tokens, rotating refresh tokens and role checks."""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
# Same scheme but returns None instead of 401 when no bearer token is sent.
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

ROLE_ADMIN, ROLE_ANALYST, ROLE_USER = "Admin", "Analyst", "User"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_USER)
PRIVILEGED_ROLES = (ROLE_ADMIN, ROLE_ANALYST)

# Verified against when the username does not exist, so a failed login costs the
# same bcrypt work either way and response time does not reveal valid usernames.
_DUMMY_HASH = pwd_context.hash(secrets.token_urlsafe(16))


def utcnow() -> datetime:
    """Naive UTC timestamp: portable across SQLite and PostgreSQL DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def verify_password_constant_time(plain_password: str, hashed_password: str | None) -> bool:
    if hashed_password is None:
        pwd_context.verify(plain_password, _DUMMY_HASH)
        return False
    return verify_password(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    now = datetime.now(timezone.utc)
    to_encode = data.copy()
    to_encode.update({
        "exp": now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
        "iat": now,
        "jti": uuid.uuid4().hex,
        "type": "access",
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate an access token; raises JWTError on any problem."""
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    if payload.get("type") != "access" or not payload.get("sub") or not payload.get("jti"):
        raise JWTError("Not an access token")
    return payload


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_refresh_token(db: Session, user_id: int) -> str:
    from app.models.models import RefreshToken
    token = secrets.token_urlsafe(48)
    db.add(RefreshToken(
        user_id=user_id,
        token_hash=hash_refresh_token(token),
        expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    return token


def revoke_access_token(db: Session, payload: dict) -> None:
    from app.models.models import RevokedAccessToken
    jti = payload.get("jti")
    if not jti or db.get(RevokedAccessToken, jti) is not None:
        return
    expires = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc).replace(tzinfo=None)
    db.add(RevokedAccessToken(jti=jti, expires_at=expires))
    # Opportunistic cleanup keeps the denylist bounded to unexpired tokens.
    db.query(RevokedAccessToken).filter(RevokedAccessToken.expires_at < utcnow()).delete()


def _credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_token_payload(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> dict:
    from app.models.models import RevokedAccessToken
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise _credentials_exception() from None
    if db.get(RevokedAccessToken, payload["jti"]) is not None:
        raise _credentials_exception()
    return payload


def get_current_user(payload: dict = Depends(get_token_payload), db: Session = Depends(get_db)):
    from app.models.models import User
    user = db.query(User).filter(User.username == payload["sub"]).first()
    # The role is always read from the database, never trusted from the token,
    # so demotion or deactivation takes effect on the next request.
    if user is None or not user.is_active:
        raise _credentials_exception()
    return user


def require_role(roles: list[str] | tuple[str, ...]):
    allowed = tuple(roles)

    def role_checker(current_user=Depends(get_current_user)):
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for current role level",
            )
        return current_user
    return role_checker


require_privileged = require_role(PRIVILEGED_ROLES)
require_admin = require_role((ROLE_ADMIN,))


def is_privileged(user) -> bool:
    return user.role in PRIVILEGED_ROLES
