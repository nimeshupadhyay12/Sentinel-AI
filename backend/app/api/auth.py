from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import login_throttle
from app.core.security import (
    ROLE_USER, create_access_token, decode_access_token, get_current_user, get_password_hash,
    hash_refresh_token, issue_refresh_token, optional_oauth2_scheme, revoke_access_token,
    utcnow, verify_password_constant_time,
)
from app.models.models import RefreshToken, User
from app.schemas.schemas import Token, UserCreate, UserOut

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

REFRESH_COOKIE = "sentinel_refresh"
REFRESH_COOKIE_PATH = "/api/auth"
GENERIC_REGISTRATION_RESPONSE = ("Registration received. If the username and email were available, "
                                 "the account is active and you can sign in.")


def _set_refresh_cookie(response: Response, token: str) -> None:
    # httpOnly: unreadable by page JavaScript, so an XSS bug cannot steal the
    # long-lived credential. SameSite=Strict + narrow path limit CSRF exposure.
    response.set_cookie(
        REFRESH_COOKIE, token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        httponly=True, secure=settings.COOKIE_SECURE, samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH,
                           secure=settings.COOKIE_SECURE, httponly=True, samesite="strict")


def _token_response(user: User) -> dict:
    return {
        "access_token": create_access_token({"sub": user.username, "uid": user.id, "role": user.role}),
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": user.role,
        "username": user.username,
    }


@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """Self-service sign-up (disabled unless ALLOW_SELF_REGISTRATION=true).

    The response is identical whether or not the username or email already
    exists (same status, same body, and the bcrypt hash is always computed), so
    the endpoint cannot be used to enumerate accounts. New accounts always get
    the least-privileged ``User`` role; administrators promote via /api/users.
    """
    if not settings.ALLOW_SELF_REGISTRATION:
        raise HTTPException(status_code=403, detail="Self-registration is disabled; ask an administrator")
    hashed = get_password_hash(user_in.password)
    exists = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)).first()
    if not exists:
        db.add(User(username=user_in.username, email=user_in.email,
                    hashed_password=hashed, role=ROLE_USER))
        try:
            db.commit()
        except IntegrityError:
            # Lost a race with a concurrent registration: same generic answer.
            db.rollback()
    return {"detail": GENERIC_REGISTRATION_RESPONSE}


@router.post("/login", response_model=Token)
def login(request: Request, response: Response,
          form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    retry_after = login_throttle.check(form_data.username, client_ip)
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
    user = db.query(User).filter(User.username == form_data.username).first()
    valid = verify_password_constant_time(form_data.password, user.hashed_password if user else None)
    if not valid or not user.is_active:
        login_throttle.record_failure(form_data.username)
        # Same message for unknown user, wrong password and disabled account.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password")
    login_throttle.record_success(form_data.username)
    _set_refresh_cookie(response, issue_refresh_token(db, user.id))
    db.commit()
    return _token_response(user)


@router.post("/refresh", response_model=Token)
def refresh(response: Response, db: Session = Depends(get_db),
            refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE)):
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if not refresh_token:
        raise invalid
    record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_refresh_token(refresh_token)).first()
    if record is None:
        _clear_refresh_cookie(response)
        raise invalid
    if record.revoked_at is not None:
        # Reuse of a rotated token: assume it was stolen and end every session.
        db.query(RefreshToken).filter(RefreshToken.user_id == record.user_id,
                                      RefreshToken.revoked_at.is_(None)).update({"revoked_at": utcnow()})
        db.commit()
        _clear_refresh_cookie(response)
        raise invalid
    user = db.get(User, record.user_id)
    if record.expires_at < utcnow() or user is None or not user.is_active:
        record.revoked_at = utcnow()
        db.commit()
        _clear_refresh_cookie(response)
        raise invalid
    record.revoked_at = utcnow()
    _set_refresh_cookie(response, issue_refresh_token(db, user.id))
    db.commit()
    return _token_response(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(db: Session = Depends(get_db), token: str | None = Depends(optional_oauth2_scheme),
           refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE)):
    """Server-side logout.

    * the presented access token's ``jti`` goes on the denylist, so the token is
      rejected immediately even though it has not expired;
    * the refresh token in the httpOnly cookie is revoked in the database.

    It deliberately works with an expired or missing access token too, so a user
    whose 15-minute token lapsed can still end the long-lived refresh session.
    """
    if token:
        try:
            revoke_access_token(db, decode_access_token(token))
        except JWTError:
            pass  # expired/invalid access token: nothing to denylist
    if refresh_token:
        db.query(RefreshToken).filter(
            RefreshToken.token_hash == hash_refresh_token(refresh_token),
            RefreshToken.revoked_at.is_(None)).update({"revoked_at": utcnow()})
    db.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(response)
    return response


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user
