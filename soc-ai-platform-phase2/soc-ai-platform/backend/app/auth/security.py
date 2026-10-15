"""Password hashing (bcrypt) and JWT helpers."""
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from app.config import get_settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except ValueError:
        return False


def create_access_token(username: str, role: str) -> tuple[str, int]:
    s = get_settings()
    exp = datetime.now(timezone.utc) + timedelta(minutes=s.jwt_expire_minutes)
    token = jwt.encode({"sub": username, "role": role, "exp": exp}, s.jwt_secret, algorithm=s.jwt_algorithm)
    return token, s.jwt_expire_minutes * 60


def decode_token(token: str) -> dict:
    s = get_settings()
    return jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
