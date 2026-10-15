"""Create the first admin user.  Run from backend/:  python seed_admin.py admin 'StrongPass123!'"""
import asyncio
import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")
from app.auth.security import hash_password  # noqa: E402
from app.db import ensure_indexes, get_db  # noqa: E402


async def main(username: str, password: str, role: str = "admin"):
    if len(password) < 10:
        sys.exit("Password must be at least 10 characters")
    db = get_db()
    await ensure_indexes(db)
    await db.users.update_one({"username": username}, {"$setOnInsert": {
        "username": username, "password_hash": hash_password(password), "role": role,
        "is_active": True, "created_at": datetime.now(timezone.utc)}}, upsert=True)
    print(f"User '{username}' ({role}) ready.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: seed_admin.py <username> <password> [role]")
    asyncio.run(main(*sys.argv[1:4]))
