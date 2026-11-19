"""Safely create or reset an administrator using explicit environment values.

Set SENTINEL_ADMIN_USERNAME and SENTINEL_ADMIN_PASSWORD before running.
No default password is embedded in this script.
"""
import os
from app.core.database import SessionLocal
from app.models.models import User
from app.core.security import get_password_hash


def reset_admin():
    username = os.getenv("SENTINEL_ADMIN_USERNAME")
    password = os.getenv("SENTINEL_ADMIN_PASSWORD")
    email = os.getenv("SENTINEL_ADMIN_EMAIL", "admin@sentinelai.local")

    if not username or not password:
        raise SystemExit(
            "Set SENTINEL_ADMIN_USERNAME and SENTINEL_ADMIN_PASSWORD before running."
        )
    if len(password) < 14:
        raise SystemExit("Use an administrator password with at least 14 characters.")

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == username).first()
        if admin is None:
            admin = User(
                username=username,
                email=email,
                hashed_password=get_password_hash(password),
                role="Admin",
            )
            db.add(admin)
        else:
            admin.hashed_password = get_password_hash(password)
            admin.role = "Admin"
        db.commit()
        print(f"Administrator account '{username}' created or updated.")
    finally:
        db.close()


if __name__ == "__main__":
    reset_admin()
