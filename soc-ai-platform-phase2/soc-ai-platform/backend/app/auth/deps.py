"""FastAPI dependencies: current user + role-based access control."""
import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.auth.security import decode_token
from app.db import get_db
from app.errors import AppError

bearer = HTTPBearer(auto_error=False)


async def get_current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if creds is None:
        raise AppError(401, "not_authenticated", "Authentication required")
    try:
        payload = decode_token(creds.credentials)
    except jwt.PyJWTError:
        raise AppError(401, "invalid_token", "Invalid or expired token")
    user = await get_db().users.find_one({"username": payload.get("sub")})
    if not user or not user.get("is_active", True):
        raise AppError(401, "invalid_token", "User not found or disabled")
    return user  # role is read from the DB, not trusted from the token


def require_roles(*roles: str):
    async def checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise AppError(403, "forbidden", "Insufficient permissions")
        return user
    return checker


require_analyst = require_roles("analyst", "admin")
require_admin = require_roles("admin")
