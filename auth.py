from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from database import Session
from models import User, Tutor

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

SECRET_KEY = "123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role not in ["user", "tutor"]:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception

    db = Session()
    if role == "user":
        user = db.query(User).filter(User.username == token_data.username).first()
    elif role == "tutor":
        user = db.query(Tutor).filter(Tutor.username == token_data.username).first()

    if user is None:
        raise credentials_exception
    return user

