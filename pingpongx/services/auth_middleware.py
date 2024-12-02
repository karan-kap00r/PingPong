import jwt
from fastapi import HTTPException, Request
from functools import wraps
import os

JWT_SECRET = os.getenv("JWT_SECRET", "pingpong_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


def verify_jwt(token: str):
    """Decode the JWT token to extract username."""
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded["username"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_auth(func):
    """Decorator to enforce authentication on endpoints."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        username = verify_jwt(token.split(" ")[1])
        kwargs["username"] = username
        return await func(*args, **kwargs)
    return wrapper
