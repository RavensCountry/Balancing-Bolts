import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.exc import UnknownHashError
from sqlmodel import Session, select
from .database import get_session
from .models import User, ResmanToken
import requests

SECRET_KEY = os.getenv('SECRET_KEY', 'devsecret_change_me')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# user utilities

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# fallback context for environments without bcrypt or for pbkdf2 hashed records
fallback_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def verify_password(plain, hashed):
    if not hashed:
        return False
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        try:
            return fallback_context.verify(plain, hashed)
        except Exception:
            return False


def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(email: str) -> Optional[User]:
    with get_session() as s:
        q = select(User).where(User.email == email).order_by(User.id.desc())
        return s.exec(q).first()

# user creation is handled in `crud.create_user` which stores `hashed_password`.

def authenticate_user(email: str, password: str) -> Optional[User]:
    u = get_user_by_email(email)
    if not u:
        return None
    if not verify_password(password, u.hashed_password):
        return None
    return u

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(email)
    if user is None:
        raise credentials_exception
    return user

def require_role(role: str):
    async def role_checker(user: User = Depends(get_current_user)):
        if user.role != role and user.role != 'admin':
            raise HTTPException(status_code=403, detail='Insufficient privileges')
        return user
    return role_checker

# ResMan OAuth helpers

def resman_authorize_url():
    client_id = os.getenv('RESMAN_CLIENT_ID')
    redirect = os.getenv('RESMAN_REDIRECT_URI')
    base = os.getenv('RESMAN_AUTHORIZE_URL', 'https://cityheightsam.auth.myresman.com/auth/connect/authorize')
    return f"{base}?client_id={client_id}&redirect_uri={redirect}&response_type=code&scope=openid profile"


def exchange_code_for_token(code: str):
    token_url = os.getenv('RESMAN_TOKEN_URL', 'https://cityheightsam.auth.myresman.com/auth/connect/token')
    client_id = os.getenv('RESMAN_CLIENT_ID')
    client_secret = os.getenv('RESMAN_CLIENT_SECRET')
    redirect = os.getenv('RESMAN_REDIRECT_URI')
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect,
        'client_id': client_id,
        'client_secret': client_secret,
    }
    resp = requests.post(token_url, data=data)
    resp.raise_for_status()
    j = resp.json()
    # store token
    expires_in = j.get('expires_in')
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None
    with get_session() as s:
        rt = ResmanToken(access_token=j.get('access_token'), refresh_token=j.get('refresh_token'), expires_at=expires_at)
        s.add(rt)
        s.commit()
        s.refresh(rt)
        return rt
