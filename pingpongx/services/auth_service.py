import os
from passlib.context import CryptContext
from pingpongx.models import SignupRequest, LoginRequest
from pingpongx.services.firestore_service import db
import datetime
import jwt
from pingpongx.utils import validate_phone_number, validate_email

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")


def generate_jwt(username: str):
    """Generate a JWT token with the username."""
    try:
        payload = {
            "username": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Token expires in 1 hour
            "iat": datetime.datetime.utcnow()
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    except Exception as e:
        print(e)
        return None


def hash_password(password: str) -> str:
    """Hash the password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against the hashed one."""
    return pwd_context.verify(plain_password, hashed_password)


def register_user(username: str, password: str):
    """Register a new user."""
    try:
        username = username.strip().lower()
        if "@" in username:
            valid_username = validate_email(username)
        else:
            valid_username = validate_phone_number(username)

        if username == "" or valid_username is None:
            return {"message": "Invalid credentials", "success": False}
        user_ref = db.collection("users").document(username)
        if user_ref.get().exists:
            return {"message": "User already exists", "success": False}

        hashed_password = hash_password(password)
        user_ref.set({
            "username": username,
            "password": hashed_password,
            "created_at": datetime.datetime.utcnow().isoformat()
        })
        return {"message": "User registered successfully", "success": True}
    except Exception as e:
        return {"message": str(e), "success": False}


def login_user(username: str, password: str):
    """Login user by verifying credentials."""
    try:
        username = username.strip().lower()
        if "@" in username:
            valid_username = validate_email(username)
        else:
            valid_username = validate_phone_number(username)

        if username == "" or valid_username is None:
            return {"message": "Username can't be empty", "success": False}
        user_ref = db.collection("users").document(username)
        user_data = user_ref.get()
        if not user_data.exists:
            return {"message": "Invalid credentials", "success": False}

        user_data = user_data.to_dict()
        if not verify_password(password, user_data["password"]):
            return {"message": "Invalid credentials", "success": False}

        token = generate_jwt(username)
        if token:
            return {"message": "Login successful", "username": username, "token": token, "success": True}
        return {"message": "Login failed!", "success": False}
    except Exception as e:
        return {"message": str(e), "success": False}


def signup(request: SignupRequest):
    """Signup API."""
    return register_user(request.username, request.password)


def login(request: LoginRequest):
    """Login API."""
    return login_user(request.username, request.password)
