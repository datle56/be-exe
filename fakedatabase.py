from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from random import randint
from models import *
from fastapi import Depends, Form, HTTPException, status
from datetime import timedelta
from database import get_db
from models import *
from auth import oauth2_scheme, Token, TokenData, create_access_token, get_current_user
from app import app
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import logging
pwd_context  = CryptContext(schemes=["bcrypt"], deprecated="auto")


engine = create_engine('sqlite:///./users.db')
Session = sessionmaker(bind=engine)
session = Session()



# Add fake data for users
for i in range(10):
    hashed_password = pwd_context.hash('password')
    user = User(
        username=f'user{i}',
        email=f'user{i}@example.com',
        password=hashed_password,
        balance=randint(100, 1000)
    )
    session.add(user)

# Add fake data for tutors
for i in range(10):
    hashed_password = pwd_context.hash('password')
    tutor = Tutor(
        username=f'tutor{i}',
        email=f'tutor{i}@example.com',
        status = 'waiting',
        password=hashed_password,
        balance=randint(100, 1000)
    )
    session.add(tutor)



session.commit()
