import os
import datetime
import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from ..database import database, models

router = APIRouter()
security = HTTPBearer(auto_error=False)

DEFAULT_INSECURE_SECRET = "soc-analytics-secret-key-change-in-production-10b981"
JWT_SECRET = os.environ.get("JWT_SECRET", DEFAULT_INSECURE_SECRET)
if JWT_SECRET == DEFAULT_INSECURE_SECRET:
    import logging
    logging.getLogger("uvicorn.warn").warning(
        "SECURITY WARNING: JWT_SECRET environment variable is not set! Using default insecure development key. Set JWT_SECRET in production."
    )
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserRegister(BaseModel):
    username: str
    password: str
    role: Optional[str] = "Analyst"

class UserLogin(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def create_access_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
):
    if not credentials:
        return None # Allow guest analyst if auth is optional
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        user = db.query(models.User).filter(models.User.username == username).first()
        return user
    except jwt.PyJWTError:
        return None

@router.post("/register")
def register_analyst(payload: UserRegister, db: Session = Depends(get_db)):
    if len(payload.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long.")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long.")

    existing = db.query(models.User).filter(models.User.username == payload.username.strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered.")

    hashed = hash_password(payload.password)
    user = models.User(
        username=payload.username.strip(),
        hashed_password=hashed,
        role=payload.role or "Analyst",
        created_at=datetime.datetime.utcnow()
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.username, user.role)
    return {
        "message": "User registered successfully",
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "username": user.username, "role": user.role}
    }

@router.post("/login")
def login_analyst(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username.strip()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Please verify username and password."
        )

    token = create_access_token(user.username, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "username": user.username, "role": user.role}
    }

@router.get("/me")
def get_current_profile(user: Optional[models.User] = Depends(get_current_user)):
    if not user:
        # Fallback guest analyst identity so user is never blocked
        return {
            "authenticated": False,
            "user": {"username": "Guest Analyst", "role": "Analyst", "guest": True}
        }
    return {
        "authenticated": True,
        "user": {"id": user.id, "username": user.username, "role": user.role, "guest": False}
    }
