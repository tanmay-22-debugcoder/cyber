import time
from collections import defaultdict, deque
from fastapi import APIRouter, Depends, Request
from app.auth.deps import get_current_user, require_admin
from app.auth.security import create_access_token, hash_password, verify_password
from app.config import get_settings
from app.db import get_db
from app.errors import AppError
from app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserOut
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timezone

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
_attempts: dict[str, deque] = defaultdict(deque)


def _check_rate_limit(key: str) -> None:
    s = get_settings()
    now = time.monotonic()
    q = _attempts[key]
    while q and now - q[0] > s.login_window_seconds:
        q.popleft()
    if len(q) >= s.login_max_attempts:
        raise AppError(429, "too_many_attempts", "Too many failed login attempts. Try again later.")


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request):
    key = f"{request.client.host if request.client else 'unknown'}:{body.username.lower()}"
    _check_rate_limit(key)
    user = await get_db().users.find_one({"username": body.username})
    # Same message for unknown user / wrong password (no user enumeration).
    if not user or not user.get("is_active", True) or not verify_password(body.password, user["password_hash"]):
        _attempts[key].append(time.monotonic())
        raise AppError(401, "invalid_credentials", "Invalid username or password")
    _attempts.pop(key, None)
    token, expires = create_access_token(user["username"], user["role"])
    return TokenResponse(access_token=token, expires_in=expires, role=user["role"])


@router.post("/logout")
async def logout(_: dict = Depends(get_current_user)):
    """JWTs are stateless: the client discards the token. (Token denylist is a documented future extension.)"""
    return {"message": "Logged out. Discard the token on the client."}


@router.get("/me", response_model=UserOut)
async def me(user: dict = Depends(get_current_user)):
    return UserOut(username=user["username"], role=user["role"], is_active=user.get("is_active", True))


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(body: UserCreate, admin: dict = Depends(require_admin)):
    doc = {"username": body.username, "password_hash": hash_password(body.password), "role": body.role,
           "is_active": True, "created_at": datetime.now(timezone.utc)}
    try:
        await get_db().users.insert_one(doc)
    except DuplicateKeyError:
        raise AppError(409, "user_exists", "Username already exists")
    await get_db().analyst_actions.insert_one({
        "incident_id": None, "user": admin["username"], "action": "user_created",
        "note": f"{body.username} ({body.role})", "timestamp": datetime.now(timezone.utc)})
    return UserOut(username=body.username, role=body.role)
