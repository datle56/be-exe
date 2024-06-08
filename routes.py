from fastapi import Depends, Form, HTTPException, status
from datetime import timedelta
from database import get_db
from models import *
from auth import oauth2_scheme, Token, TokenData, create_access_token, get_current_user
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import logging
logging.getLogger('passlib').setLevel(logging.ERROR)
from sqlalchemy import func
from typing import List
from schemas import *
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import shutil
from pydantic import BaseModel, Field
from enum import Enum
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import desc
import pathlib
import textwrap
from fastapi import FastAPI, WebSocket
from starlette.responses import HTMLResponse
import google.generativeai as genai
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import markdown2
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import Dict
from collections import deque
from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks
import json
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from database import Session
from auth import oauth2_scheme, Token, TokenData, create_access_token, get_current_user
from routes import *
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import Dict
from collections import deque
from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks
import json
app = FastAPI()
genai.configure(api_key='')
model = genai.GenerativeModel('gemini-pro')
#Tutor home chua sua 
# origins = [
#     "http://speak.id.vn",
#     "https://speak.id.vn",
#     "http://localhost",
#     "http://localhost:3000",
#     "https://www.speak.id.vn",
# ]

# # Add CORS middleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],  # Allows all methods
#     allow_headers=["*"],
# )
class CustomCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        origin = request.headers.get('origin')
        if origin and (origin.endswith(".speak.id.vn") or origin == "http://localhost:3000"):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = '*'
            response.headers['Access-Control-Allow-Headers'] = '*'
        return response

app.add_middleware(CustomCORSMiddleware)
pwd_context  = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

app.mount("/api/CV", StaticFiles(directory="CV"), name="CV")

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Your Application",
        version="1.0.0",
        description="This is a very custom OpenAPI schema",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2": {
            "type": "oauth2",
            "flows": {
                "password": {
                    "tokenUrl": "/token",
                    "scopes": {}
                }
            }
        }
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    db = next(get_db())

    user = db.query(User).filter(User.username == username).first()
    tutor = db.query(Tutor).filter(Tutor.username == username).first()

    if not user and not tutor:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if user and pwd_context.verify(password, user.password):
        role = "user"
    elif tutor and pwd_context.verify(password, tutor.password):
        role = "tutor"
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token_expires = timedelta(minutes=90)
    access_token = create_access_token(data={"sub": username, "role": role, "username": username}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer", "role": role,"username": username  }

@app.post("/api/register")
async def register(username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form(...)):
    db: Session = next(get_db())

    # Check if the username already exists
    user = db.query(User).filter(User.username == username).first()
    tutor = db.query(Tutor).filter(Tutor.username == username).first()
    if user or tutor:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash the password
    hashed_password = pwd_context.hash(password)

    detail_info = None
    new_package = None

    # Create a new user or tutor depending on the role
    if role == "user":
        new_user = User(username=username, email=email, password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        # Create an entry in DetailInformation with the new user's ID
        detail_info = DetailInformation(user_id=new_user.id, tutor_id=None, firstname='', lastname='', address='', phone_number='', aboutme='', bankname='', banknumber='')
        # Create a new Package entry for the user with all packages set to 0
        new_package = Package(user_id=new_user.id, remaining_learning_sessions=0, remaining_ai_conversations=0)
    elif role == "tutor":
        new_tutor = Tutor(username=username, email=email, password=hashed_password)
        db.add(new_tutor)
        db.commit()
        db.refresh(new_tutor)
        # Create an entry in DetailInformation with the new tutor's ID
        detail_info = DetailInformation(user_id=None, tutor_id=new_tutor.id, firstname='', lastname='', address='', phone_number='', aboutme='', bankname='', banknumber='')

    # Add the detail information entry
    db.add(detail_info)
    # Add the new package entry if it was created
    if new_package:
        db.add(new_package)
    db.commit()

    return {"username": username, "email": email, "role": role, "message": "Registration successful"}

    return {"username": username, "email": email, "role": role, "message": "Registration successful"}

@app.get("/api/tutor/status")
async def check_status(user: User = Depends(get_current_user)):
    db = next(get_db())
    username = user.username

    tutor = db.query(Tutor).filter(Tutor.username == username).first()
    st = tutor.status 
    print(st)
    return {"status": st}

# @app.get("/tutor/home")
# async def get_tutor_home_info(user: User = Depends(get_current_user)):
#     db = next(get_db())
#     username = user.username
    
#     # Get the tutor
#     tutor = db.query(Tutor).filter(Tutor.username == username).first()

#     if tutor is None:
#         return {"message": "Tutor not found"}

#     # Get the dates for the last 7 days
#     dates = [datetime.now() - timedelta(days=i) for i in range(7)]

#     # Get the teaching time for each day
#     teaching_times = []
#     for date in dates:
#         teaching_time = db.query(func.sum(DailyTeachingTime.teaching_time)).filter(DailyTeachingTime.tutor_id == tutor.id, DailyTeachingTime.date == date.date()).scalar()
#         teaching_times.append({
#             "date": date.date().isoformat(),
#             "teaching_time": teaching_time if teaching_time is not None else 0
#         })

#     # Get the average rating
#     average_rating = db.query(func.avg(Review.rating)).filter(Review.tutor_id == tutor.id).scalar()

#     return {
#         "email": tutor.id ,
#         "balance": tutor.balance,
#         "teaching_times_last_7_days": teaching_times,
#         "average_rating": average_rating if average_rating is not None else 5
#     }



@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = next(get_db())
    user = db.query(User).filter(User.username == form_data.username).first()
    tutor = db.query(Tutor).filter(Tutor.username == form_data.username).first()

    if not user and not tutor:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    if user and not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    elif tutor and not pwd_context.verify(form_data.password, tutor.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    if user:
        role = "user"
    else:
        role = "tutor"

    access_token_expires = timedelta(minutes=90)
    access_token = create_access_token(data={"sub": form_data.username, "role": role, "username": form_data.username}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}


#USER

@app.get("/api/user/home")
async def get_user_home_info(user: User = Depends(get_current_user)):
    db = next(get_db())
    username = user.username

    # Get the user
    user = db.query(User).filter(User.username == username).first()
    print(user)
    if user is None:
        return {"message": "User not found"}

    # Get the dates for the last 7 days
    dates = [datetime.now() - timedelta(days=i) for i in range(7)]

    # Get the learning time for each day
    learning_times = []
    for date in dates:
        learning_time = db.query(DailyLearningTime.learning_time).filter(DailyLearningTime.user_id == user.id, DailyLearningTime.date == date.date()).scalar()
        learning_times.append({
            "date": date.date().isoformat(),
            "learning_time": learning_time if learning_time is not None else 0
        })

    return {
        "username": user.username,
        "email": user.email,
        "balance": user.balance,
        "learning_times_last_7_days": learning_times
    }
class PaymentIn(BaseModel):
     amount: int
@app.post("/api/user/payment")
async def create_payment(payment: PaymentIn, user: User = Depends(get_current_user)):
    db = next(get_db())
    username = user.username

    user = db.query(User).filter(User.username == username).first()
    id = user.id
    transaction_type = 'deposit'
    new_payment = Payment(
        amount=payment.amount,
        timestamp=datetime.now(),
        user_id=id,
        status='waiting',
        transaction_type = transaction_type

    )
    db.add(new_payment)
    try:
        db.commit()
        return {"message": "Thanh toán thành công"}
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Thanh toán không thành công")

@app.get("/api/user/payments")
async def get_payments(user: User = Depends(get_current_user)):
    db = next(get_db())
    username = user.username
    user = db.query(User).filter(User.username == username).first()

    if user is None:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại")

    payments = db.query(Payment).filter(Payment.user_id == user.id).all()

    return {"payments": [payment.__dict__ for payment in payments]}

@app.get("/api/admin/payments")
async def get_all_payments():
    db = next(get_db())
    payments = db.query(Payment, User).join(User, Payment.user_id == User.id).all()

    
    return {"payments": [{"id": payment.id, "amount": payment.amount, "timestamp": payment.timestamp, "status": payment.status, "username": user.username} for payment, user in payments]}

@app.put("/api/admin/payments/{payment_id}")
async def update_payment_status(payment_id: int, status: str):
    db = next(get_db())
    payment = db.query(Payment).filter(Payment.id == payment_id).first()

    if payment is None:
        raise HTTPException(status_code=404, detail="Thanh toán không tồn tại")

    if status == 'accept':
        user = db.query(User).filter(User.id == payment.user_id).first()
        user.balance += payment.amount

    payment.status = status
    db.commit()

    return {"message": "Cập nhật trạng thái thanh toán thành công"}


@app.get("/api/admin/tutor/payments")
async def get_all_tutors_payments():
    db = next(get_db())
    payments = db.query(Payment, Tutor).join(Tutor, Payment.tutor_id == Tutor.id).all()

    return {"payments": [{"id": payment.id, "amount": payment.amount, "timestamp": payment.timestamp, "status": payment.status, "username": user.username} for payment, user in payments]}

@app.put("/admin/tutor/payment/{payment_id}")
async def update_payment_status(payment_id: int, status: str):
    db = next(get_db())
    payment = db.query(Payment).filter(Payment.id == payment_id).first()

    if payment is None:
        raise HTTPException(status_code=404, detail="Thanh toán không tồn tại")

    tutor = db.query(Tutor).filter(Tutor.id == payment.tutor_id).first()

    if status == 'decline' and payment.status != 'decline':
        tutor.balance += payment.amount  # Add the amount back to the tutor's balance if the request is declined

    payment.status = status
    db.commit()

    return {"message": "Cập nhật trạng thái thanh toán thành công"}


@app.post("/tutor/withdraw")
async def create_withdrawal(payment: PaymentIn, tutor: Tutor = Depends(get_current_user)):
    db = next(get_db())
    username = tutor.username

    tutor = db.query(Tutor).filter(Tutor.username == username).first()
    if tutor.balance >= payment.amount:
        id = tutor.id
        print(id)
        transaction_type = 'withdraw'
        new_payment = Payment(
            amount=payment.amount,
            timestamp=datetime.now(),
            tutor_id=id,
            status='waiting',
            transaction_type = transaction_type
        )
        db.add(new_payment)
        tutor.balance -= payment.amount  # Deduct the amount from the tutor's balance immediately
        try: 
            db.commit()
            return {"message": "Yêu cầu rút tiền đã được gửi"}
        except:
            db.rollback()
            raise HTTPException(status_code=400, detail="Rút tiền không thành công")
    else:
        return {"message": "Số dư không đủ"}

    

@app.get("/api/tutor/payments")
async def get_withdrawals(tutor: Tutor = Depends(get_current_user)):
    db = next(get_db())
    username = tutor.username
    tutor = db.query(Tutor).filter(Tutor.username == username).first()

    if tutor is None:
        raise HTTPException(status_code=404, detail="Gia sư không tồn tại")

    payments = db.query(Payment).filter(Payment.tutor_id == tutor.id).order_by(Payment.timestamp.desc()).all()

    return {"payments": [payment.__dict__ for payment in payments]}

@app.get("/api/admin/users")
async def get_users(skip: int = 0, limit: int = 100):
    db = next(get_db())
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@app.delete("/api/admin/users/{user_id}")
async def delete_user(user_id: int):
    db = next(get_db())
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return {"message": "User deleted"}

@app.put("/api/admin/users/{user_id}")
async def update_user(user_id: int, balance: int):
    db = next(get_db())
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db_user.balance = balance
    db.commit()
    return {"message": "User updated"}

class TutorStatus(str, Enum):
    waiting = "waiting"
    accept = "accept"
    decline = "decline"

@app.get("/api/admin/tutors")
async def get_tutors(skip: int = 0, limit: int = 100):
    db = next(get_db())
    tutors = db.query(Tutor).offset(skip).limit(limit).all()
    return tutors


@app.put("/api/admin/tutors/{tutor_id}")
async def update_tutor(tutor_id: int, balance: int, status: Optional[TutorStatus] = None):
    db = next(get_db())
    db_tutor = db.query(Tutor).filter(Tutor.id == tutor_id).first()
    if db_tutor is None:
        raise HTTPException(status_code=404, detail="Tutor not found")
    db_tutor.balance = balance
    if status is not None:
        db_tutor.status = status
    db.commit()
    return {"message": "Tutor updated"}

@app.delete("/api/admin/users/{user_id}")
async def delete_user(user_id: int):
    db = next(get_db())
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return {"message": "User deleted"}

class CV(BaseModel):
    id: int
    username: str
    cv: str
    timestamp: str
    status: str

@app.get("/api/admin/cv/history")
async def get_cv_history(skip: int = 0, limit: int = 100):
    db = next(get_db())
    cv_history = db.query(CVHistory).offset(skip).limit(limit).all()
    return cv_history

@app.put("/api/admin/cv/{cv_id}")
async def update_cv_status(cv_id: int, status: str):
    db = next(get_db())
    db_cv = db.query(CVHistory).filter(CVHistory.id == cv_id).first()
    if db_cv is None:
        raise HTTPException(status_code=404, detail="CV not found")
    
    db_tutor = db.query(Tutor).filter(Tutor.id == db_cv.tutor_id).first()
    if db_tutor is None:
        raise HTTPException(status_code=404, detail="Tutor not found")

    db_cv.status = status
    db_tutor.status = status
    db.commit()
    return {"message": "CV and Tutor status updated"}

@app.get("/api/admin/cv/{cv_id}")
async def get_cv(cv_id: int):
    return FileResponse(f'./CV/{cv_id}.pdf', media_type='application/pdf')

@app.post("/api/tutor/cv/upload")
async def upload_cv_pdf(cv: UploadFile = File(...),tutor: Tutor = Depends(get_current_user)):
    db = next(get_db())
    username = tutor.username
    tutor = db.query(Tutor).filter(Tutor.username == username).first()
    root = './CV/'
    # Save the file with the name as tutor_id.pdf
    with open(root + f"{tutor.id}.pdf", "wb") as buffer:
        buffer.write(await cv.read())
    
    # Add a record to CV history
    cv_history = CVHistory(tutor_id=tutor.id, status='waiting')
    db.add(cv_history)
    db.commit()

    return {"message": "CV uploaded successfully"}

@app.get("/api/tutor/cv/history")
async def get_cv_history(tutor: Tutor = Depends(get_current_user)):
    db = next(get_db())
    username = tutor.username
    print(username)
    tutor = db.query(Tutor).filter(Tutor.username == username).first()

    cv_history = db.query(CVHistory).filter(CVHistory.tutor_id == tutor.id).all()

    return cv_history


# class Status(str, Enum):
#     waiting = "waiting"
#     accept = "accept"
#     decline = "decline"

# @app.get("/admin/cv/history")
# async def get_cv_history():
#     db = next(get_db())
#     cv_history = db.query(CVHistory).all()
#     return cv_history



SECRET_KEY = "123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
class ConnectionManager:
    def __init__(self):
        self.active_connections = {}
        self.online_users = 0
        self.online_tutors = 0
        self.user_queue = deque()
        self.tutor_queue = deque()
        self.matched_pairs = []

    async def connect(self, websocket: WebSocket, user_id: str, user_type: str, topic: str):
        await websocket.accept()
        self.active_connections[user_id] = {"socket": websocket, "type": user_type, "topic": topic}
        if user_type == "user":
            self.online_users += 1
            self.user_queue.append(user_id)
        elif user_type == "tutor":
            self.online_tutors += 1
            self.tutor_queue.append(user_id)
        print(f"Online users: {self.online_users}, online tutors: {self.online_tutors}")  # Print the number of online users and tutors
        await self.match_users()

    async def match_users(self):
        db = next(get_db())
        print("Matching users...")
        print(f"User Queue: {self.user_queue}")
        print(f"Tutor Queue: {self.tutor_queue}")
        while self.user_queue and self.tutor_queue:
            user_id = self.user_queue.popleft()
            tutor_id = self.tutor_queue.popleft()
            user_info = self.active_connections[user_id]
            tutor_info = self.active_connections[tutor_id]
            self.matched_pairs.append({"user": user_id, "tutor": tutor_id})
            user_socket = user_info["socket"]
            tutor_socket = tutor_info["socket"]
            topic = user_info["topic"]
            link = f'https://ngocdat.id.vn/{topic}-{user_id}'
            
            start_time = datetime.now()
            end_time = start_time + timedelta(hours=1)

            # Retrieve real IDs based on usernames
            user = db.query(User).filter(User.username == user_id).first()
            tutor = db.query(Tutor).filter(Tutor.username == tutor_id).first()

            new_meeting = Meeting(
                link=link,
                start_time=start_time,
                end_time=end_time,
                status='upcoming',
                user_id=user.id,
                tutor_id=tutor.id,
                topic=topic  # Thêm topic vào đây
            )
            db.add(new_meeting)
            db.commit()

            # Create a new review with the user_id and tutor_id
            new_review = Review(
                user_id=user.id,
                tutor_id=tutor.id,
                meeting_id=new_meeting.id
            )
            db.add(new_review)
            db.commit()

            # Decrement remaining learning sessions for user
            package = db.query(Package).filter(Package.user_id == user.id).first()
            if package and package.remaining_learning_sessions > 0:
                package.remaining_learning_sessions -= 1
                db.commit()
            else:
                raise AttributeError("User has no packages or no remaining learning sessions")

            # Add entry to TutorEarningsHistory
            base_earnings = 60000
            new_earning = TutorEarningsHistory(
                tutor_id=tutor.id,
                date=start_time.date(),
                session_id=new_meeting.id,
                base_earnings=base_earnings,
                total_earnings=base_earnings
            )
            db.add(new_earning)
            db.commit()

            # Update tutor's balance
            tutor.balance += base_earnings
            db.commit()

            await user_socket.send_json({"redirect_url": 'https://speak.id.vn/user/meeting'})
            await tutor_socket.send_json({"redirect_url": 'https://speak.id.vn/tutor/meeting'})

        db.close()

# class ConnectionManager:
#     def __init__(self):
#         self.active_connections: Dict[str, WebSocket] = {}
#         self.online_users = 0
#         self.online_tutors = 0
#         self.user_queue = deque()
#         self.tutor_queue = deque()
#         self.matched_pairs = []

#     async def connect(self, websocket: WebSocket, user_id: str, user_type: str):
#         await websocket.accept()
#         self.active_connections[user_id] = {"socket": websocket, "type": user_type}
#         if user_type == "user":
#             self.online_users += 1
#             self.user_queue.append(user_id)
#         elif user_type == "tutor":
#             self.online_tutors += 1
#             self.tutor_queue.append(user_id)
#         print(f"Online users: {self.online_users}, online tutors: {self.online_tutors}")  # Print the number of online users and tutors
#         await self.match_users()

#     async def match_users(self):
#         db = next(get_db())
#         print("Matching users...")
#         print(f"User Queue: {self.user_queue}")
#         print(f"Tutor Queue: {self.tutor_queue}")
#         while self.user_queue and self.tutor_queue:
#             user_id = self.user_queue.popleft()
#             tutor_id = self.tutor_queue.popleft()
#             self.matched_pairs.append({"user": user_id, "tutor": tutor_id})
#             user_socket = self.active_connections[user_id]["socket"]
#             tutor_socket = self.active_connections[tutor_id]["socket"]
            
#             redirect_url = f"https://solulu4u.com/test"
#             start_time = datetime.now()
#             end_time = start_time + timedelta(hours=1)

       
#             #Bi nham user id voi user name
#             user_id_real = db.query(User).filter(User.username == user_id).first().id
#             tutor_id_real = db.query(Tutor).filter(Tutor.username == tutor_id).first().id

#             new_meeting = Meeting(
#                 link=redirect_url,
#                 start_time=start_time,
#                 end_time=end_time,
#                 status='upcoming',
#                 user_id=user_id_real,
#                 tutor_id=tutor_id_real
#             )
#             db.add(new_meeting)
#             db.commit()
#             await user_socket.send_json({"redirect_url": redirect_url})
#             await tutor_socket.send_json({"redirect_url": redirect_url})

            

    def disconnect(self, user_id: str):
        user_type = self.active_connections[user_id]["type"]
        del self.active_connections[user_id]
        if user_type == "user":
            self.online_users -= 1
            if user_id in self.user_queue:
                self.user_queue.remove(user_id)
        elif user_type == "tutor":
            self.online_tutors -= 1
            if user_id in self.tutor_queue:
                self.tutor_queue.remove(user_id)

    async def send_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

manager = ConnectionManager()
@app.websocket("/api/grammar/1")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            response = model.generate_content("Bạn hãy đóng vai trò là người sửa ngữ pháp cho tôi, hãy sửa lại ngữ pháp cho tôi một cách chi tiết chỉ lỗi sai và giải thích, đồng thời có thể gợi ý các từ hoặc mẫu câu hoặc cấu trúc câu mới có thể viết lại hay hơn, hãy trả lời thân mật như là một người giáo viên, giọng điệu giống một con người đầy đủ cấu trúc sau đây là câu cần sửa: \"" + data + "\"")
            text = response.text
            text = markdown2.markdown(text)
            await websocket.send_text(text)
    except WebSocketDisconnect:
        pass

@app.websocket("/api/grammar/2")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            response = model.generate_content("Hãy sửa ngữ pháp câu này cho tôi thành câu đúng, chỉ cần đưa đáp án không cần giải thích: ,  \"" + data + "\"")
            text = response.text
            text = markdown2.markdown(text)
            await websocket.send_text(text)
    except WebSocketDisconnect:
        pass


# Backup dung ngay 6/8
# @app.websocket("/api/ws/{user_id}/{user_type}")
# async def websocket_endpoint(websocket: WebSocket, user_id: str, user_type: str, background_tasks: BackgroundTasks):
#     await manager.connect(websocket, user_id, user_type)
#     try:
#         while True:
#             data = await websocket.receive_text()
#             if data == "ping":
#                 if manager.online_users > 0 and manager.online_tutors > 0:
#                     background_tasks.add_task(manager.match_users, background_tasks)
#                 await websocket.send_json({"users": manager.online_users, "user_ids": [conn for conn, details in manager.active_connections.items() if details["type"] == "user"],
#                                            "tutors": manager.online_tutors, "tutor_ids": [conn for conn, details in manager.active_connections.items() if details["type"] == "tutor"],
#                                            "matched_pairs": manager.matched_pairs})
#     except WebSocketDisconnect:
#         manager.disconnect(user_id)

@app.websocket("/api/ws/{user_id}/{user_type}/{topic}")
async def websocket_endpoint(websocket: WebSocket, user_id: str, user_type: str, topic: str, background_tasks: BackgroundTasks):
    await manager.connect(websocket, user_id, user_type, topic)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                if manager.online_users > 0 and manager.online_tutors > 0:
                    background_tasks.add_task(manager.match_users, background_tasks)
                await websocket.send_json({"users": manager.online_users, "user_ids": [conn for conn, details in manager.active_connections.items() if details["type"] == "user"],
                                           "tutors": manager.online_tutors, "tutor_ids": [conn for conn, details in manager.active_connections.items() if details["type"] == "tutor"],
                                           "matched_pairs": manager.matched_pairs})
    except WebSocketDisconnect:
        manager.disconnect(user_id)

class UserStatusManager:
    def __init__(self):
        self.active_users: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_name: str, user_type: str):
        await websocket.accept()
        self.active_users[user_name] = {"socket": websocket, "type": user_type}
        
        # Cập nhật trạng thái online và thời gian đăng nhập cuối cùng
        db = next(get_db())
        if user_type == "user":
            user = db.query(User).filter(User.username == user_name).first()
            print(user)
            if user:
                print(user)
                user.online_status = 'online'
                user.last_login = datetime.now()
        elif user_type == "tutor":
            tutor = db.query(Tutor).filter(Tutor.username == user_name).first()
            if tutor:
                tutor.online_status = 'online'
                tutor.last_login = datetime.now()
        db.commit()
    async def disconnect(self, user_id: str):
        user_type = self.active_users[user_id]["type"]
        del self.active_users[user_id]
        
        # Cập nhật trạng thái offline
        db = next(get_db())
        if user_type == "user":
            user = db.query(User).filter(User.username == user_id).first()
            if user:
                user.online_status = 'offline'
        elif user_type == "tutor":
            tutor = db.query(Tutor).filter(Tutor.username == user_id).first()
            if tutor:
                tutor.online_status = 'offline'
        db.commit()

online = UserStatusManager()

@app.websocket("/api/online/{user_id}/{user_type}")
async def websocket_endpoint(websocket: WebSocket, user_id: str, user_type: str):
    await online.connect(websocket, user_id, user_type)
    try:
        while True:
            data = await websocket.receive_text()
            # Xử lý dữ liệu nhận được từ websocket tại đây
    except WebSocketDisconnect:
        await online.disconnect(user_id)




@app.get("/home")
async def read_home(background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    print("Entered /home route")
    if ["role"] == "user":
        print("Current user is a user")
        user_id = current_user["user"].username
        manager.user_queue.append(user_id)
        print(f"User {user_id} added to the queue")
        background_tasks.add_task(manager.match_users)  # Add match_users to the background tasks
        return {"message": f"User {user_id} has been added to the queue. Please wait for a tutor to connect."}
    elif current_user["role"] == "tutor":
        print("Current user is a tutor")
        tutor_id = current_user["user"].username
        manager.tutor_queue.append(tutor_id)
        print(f"Tutor {tutor_id} added to the queue")
        background_tasks.add_task(manager.match_users)  # Add match_users to the background tasks
        return {"message": f"Tutor {tutor_id} has been added to the queue. Please wait for a user to connect."}
    
    print("No match found")
    return {"message": "No match found"}

@app.get("/home")
async def read_home(current_user: User = Depends(get_current_user)):
    await manager.match_users()
    return {"message": "Welcome to the home page!"}




@app.websocket("/api/ws/meeting")
async def websocket_endpoint(websocket: WebSocket):
    db: Session = next(get_db())
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            data = json.loads(data)
            role = data.get('role')
            username = data.get('username')

            if role == 'user':
                user = db.query(User).filter(User.username == username).first()
                if user:
                    meeting = db.query(Meeting).filter(Meeting.user_id == user.id).order_by(desc(Meeting.end_time)).first()
                    if meeting:
                        remaining_minutes = (meeting.end_time - datetime.now()).total_seconds() / 60
                        if remaining_minutes < 0:
                            await websocket.send_json({
                                "message": "Bạn không có buổi học nào hiện tại."
                            })
                        else:
                            await websocket.send_json({
                                "link": meeting.link,
                                "status": meeting.status,
                                "remaining_minutes": remaining_minutes
                            })
                    else:
                        await websocket.send_json({
                            "message": "Bạn không có buổi học nào hiện tại."
                        })

            elif role == 'tutor':
                tutor = db.query(Tutor).filter(Tutor.username == username).first()
                if tutor:
                    meeting = db.query(Meeting).filter(Meeting.tutor_id == tutor.id, Meeting.status == 'upcoming').first()
                    if meeting:
                        remaining_minutes = (meeting.end_time - datetime.now()).total_seconds() / 60
                        if remaining_minutes < 0:
                            meeting.status = 'completed'
                            db.commit()
                            await websocket.send_json({
                                "message": "Cuộc họp đã kết thúc."
                            })
                        else:
                            await websocket.send_json({
                                "link": meeting.link,
                                "status": meeting.status,
                                "remaining_minutes": remaining_minutes
                            })
                    else:
                        await websocket.send_json({
                            "message": "Bạn không có buổi học nào hiện tại."
                        })
    except WebSocketDisconnect as e:
        # Handle disconnection
        print("WebSocket disconnected:", e)
# Pydantic Model for Response
class MeetingResponse(BaseModel):
    id: int
    start_time: str
    user_name: str
    user_feedback: Optional[str]
    user_rating: Optional[int]
    tutor_feedback: Optional[str]
    tutor_rating: Optional[int]
    tutor_name: str  # Thêm trường tutor_name
    reviewed: bool  # Thêm trường reviewed
    topic : str

    class Config:
        orm_mode = True



class UserMeetingResponse(BaseModel):
    id: int
    start_time: str
    user_feedback: Optional[str]
    user_rating: Optional[int]
    tutor_feedback: Optional[str]
    tutor_rating: Optional[int]
    tutor_name: str  # Thêm trường tutor_name
    reviewed: bool  # Thêm trường reviewed
    topic : str

    class Config:
        orm_mode = True


# @app.get("/user/meetings")
# def get_meetings(user: User = Depends(get_current_user)):
#     db = next(get_db())
#     user_in_db = db.query(User).filter(User.username == user.username).first()
#     meetings = db.query(Meeting).join(Tutor, Meeting.tutor_id == Tutor.id).filter(Meeting.user_id == user_in_db.id).all()
    
#     # Format the response
#     meeting_responses = [
#         MeetingResponse(
#             link=meeting.link,
#             start_time=meeting.start_time,
#             end_time=meeting.end_time,
#             status=meeting.status,
#             tutor_name=meeting.tutor.username
#         ) for meeting in meetings
#     ]
    
#     return meeting_responses


# @app.get("/api/user/meetings")
# def get_meetings(current_user: User = Depends(get_current_user)):
#     db = next(get_db())
#     user_in_db = db.query(User).filter(User.username == current_user.username).first()
#     meetings = db.query(Meeting).join(Tutor, Meeting.tutor_id == Tutor.id).filter(Meeting.user_id == user_in_db.id).all()
    
#     meeting_responses = []
#     for meeting in meetings:
#         review = db.query(Review).filter(Review.meeting_id == meeting.id).first()
#         if review:
#             meeting_responses.append(UserMeetingResponse(
#                 id=meeting.id,
#                 start_time=meeting.start_time.isoformat(),
#                 tutor_name=meeting.tutor.username,
#                 user_feedback=review.user_feedback,
#                 user_rating=review.user_rating,
#                 tutor_feedback=review.tutor_feedback,
#                 tutor_rating=review.tutor_rating,
#                 user_suggest=review.user_suggest,  # Add this line
#                 tutor_suggest=review.tutor_suggest,  # Add this line
#                 reviewed=review.user_reviewed
#             ))
#         else:
#             meeting_responses.append(UserMeetingResponse(
#                 id=meeting.id,
#                 start_time=meeting.start_time,
#                 tutor_name=meeting.tutor.username,
#                 user_feedback=None,
#                 user_rating=None,
#                 tutor_feedback=None,
#                 tutor_rating=None,
#                 user_suggest=None,  # Add this line
#                 tutor_suggest=None,  # Add this line
#                 reviewed=False
#             ))
#     db.commit()
#     return meeting_responses

class ReviewCreate(BaseModel):
    user_rating: Optional[int] = None
    user_feedback: Optional[str] = None
    tutor_rating: Optional[int] = None
    tutor_feedback: Optional[str] = None
    user_suggest: Optional[str] = None  # Add this line
    tutor_suggest: Optional[str] = None  # Add this line
    meeting_id: int



class UserReviewCreate(BaseModel):
    user_rating: Optional[int] = None
    user_feedback: Optional[str] = None
    user_suggest: Optional[str] = None  # Add this line
    meeting_id: int




@app.put("/api/user/review")
def update_review(review: UserReviewCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_in_db = db.query(User).filter(User.username == current_user.username).first()
    meeting = db.query(Meeting).filter(Meeting.id == review.meeting_id).first()

    if not meeting or meeting.user_id != user_in_db.id:
        raise HTTPException(status_code=400, detail="Invalid meeting ID")

    review_in_db = db.query(Review).filter(Review.meeting_id == review.meeting_id).first()
    if not review_in_db:
        raise HTTPException(status_code=404, detail="Review not found")

    # Update the review fields
    review_in_db.user_rating = review.user_rating
    review_in_db.user_feedback = review.user_feedback
    review_in_db.user_suggest = review.user_suggest
    review_in_db.user_reviewed = True

    db.commit()
    db.refresh(review_in_db)

    return review_in_db




@app.get("/api/tutor/meetings", response_model=List[MeetingResponse])
def get_meetings(current_user: User = Depends(get_current_user)):
    db = next(get_db())
    tutor_in_db = db.query(Tutor).filter(Tutor.username == current_user.username).first()
    if not tutor_in_db:
        raise HTTPException(status_code=404, detail="Tutor not found")

    meetings = db.query(Meeting).filter(Meeting.tutor_id == tutor_in_db.id).all()
    meetings_with_reviews = []
    for meeting in meetings:
        review = db.query(Review).filter(Review.meeting_id == meeting.id).first()
        if review:
            meetings_with_reviews.append({
                "id": meeting.id,
                "start_time": meeting.start_time.isoformat(),
                "user_name": meeting.user.username,
                "user_feedback": review.user_feedback,
                "user_rating": review.user_rating,
                "tutor_feedback": review.tutor_feedback,
                "tutor_rating": review.tutor_rating,
                "tutor_name": tutor_in_db.username,  # Lấy tên tutor
                "reviewed": review.user_reviewed and review.tutor_reviewed,  # Xác định đã được review hay chưa
                "topic" : meeting.topic
            })
    print(meetings_with_reviews)
    return meetings_with_reviews

@app.put("/api/tutor/review")
def update_tutor_review(review: TutorReviewCreate, current_user: User = Depends(get_current_user)):
    db = next(get_db())
    tutor_in_db = db.query(Tutor).filter(Tutor.username == current_user.username).first()
    if not tutor_in_db:
        raise HTTPException(status_code=404, detail="Tutor not found")

    meeting = db.query(Meeting).filter(Meeting.id == review.meeting_id).first()
    if not meeting or meeting.tutor_id != tutor_in_db.id:
        raise HTTPException(status_code=400, detail="Invalid meeting ID")

    review_in_db = db.query(Review).filter(Review.meeting_id == review.meeting_id).first()
    if not review_in_db:
        raise HTTPException(status_code=404, detail="Review not found")

    # Update the review fields
    review_in_db.tutor_rating = review.tutor_rating
    review_in_db.tutor_feedback = review.tutor_feedback
    review_in_db.tutor_suggest = review.tutor_suggest
    review_in_db.tutor_reviewed = True

    db.commit()
    db.refresh(review_in_db)

    return review_in_db




class UserUpdate(BaseModel):
    firstname: str = None
    lastname: str = None
    address: str = None
    phone_number: str = None
    aboutme: str = None
    bankname: str = None
    banknumber: str = None
    role :str = None 

@app.get("/api/get-profile/{role}")
def get_profile(role: str, current_user: User = Depends(get_current_user)):
    db: Session = next(get_db())
    
    if role == "user":
        user = db.query(User).filter(User.id == current_user.id).first()
        if user:
            detail_info = db.query(DetailInformation).filter(DetailInformation.user_id == user.id).first()
            return {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "firstname": detail_info.firstname if detail_info else "",
                "lastname": detail_info.lastname if detail_info else "",
                "address": detail_info.address if detail_info else "",
                "phone_number": detail_info.phone_number if detail_info else "",
                "aboutme": detail_info.aboutme if detail_info else "",
                "bankname": detail_info.bankname if detail_info else "",
                "banknumber": detail_info.banknumber if detail_info else "",
                "role": "user"
            }
    elif role == "tutor":
        tutor = db.query(Tutor).filter(Tutor.id == current_user.id).first()
        if tutor:
            detail_info = db.query(DetailInformation).filter(DetailInformation.tutor_id == tutor.id).first()
            return {
                "user_id": tutor.id,
                "username": tutor.username,
                "email": tutor.email,
                "firstname": detail_info.firstname if detail_info else "",
                "lastname": detail_info.lastname if detail_info else "",
                "address": detail_info.address if detail_info else "",
                "phone_number": detail_info.phone_number if detail_info else "",
                "aboutme": detail_info.aboutme if detail_info else "",
                "bankname": detail_info.bankname if detail_info else "",
                "banknumber": detail_info.banknumber if detail_info else "",
                "role": "tutor"
            }
    raise HTTPException(status_code=404, detail="Profile not found")


#LOI HIEN THI, TUTOR NÓ VẪN HIỂN THỊ RA THÔNG TIN USER 
@app.put("/api/update-profile")
def update_profile(user_update: UserUpdate, current_user: User = Depends(get_current_user)):
    db: Session = next(get_db())
    if user_update.role == 'user':
        user_in_db = db.query(User).filter(User.id == current_user.id).first()
        detail_info = db.query(DetailInformation).filter(DetailInformation.user_id == user_in_db.id).first()

    elif user_update.role == 'tutor' :
        tutor_in_db = db.query(Tutor).filter(Tutor.id == current_user.id).first()
        detail_info = db.query(DetailInformation).filter(DetailInformation.tutor_id == tutor_in_db.id).first()

    else:
        raise HTTPException(status_code=404, detail="User not found")

    if detail_info:
        if user_update.firstname is not None:
            detail_info.firstname = user_update.firstname
        if user_update.lastname is not None:
            detail_info.lastname = user_update.lastname
        if user_update.address is not None:
            detail_info.address = user_update.address
        if user_update.phone_number is not None:
            detail_info.phone_number = user_update.phone_number
        if user_update.aboutme is not None:
            detail_info.aboutme = user_update.aboutme
        if user_update.bankname is not None:
            detail_info.bankname = user_update.bankname
        if user_update.banknumber is not None:
            detail_info.banknumber = user_update.banknumber
    else:
        if user_update.role == "user":
            detail_info = DetailInformation(
                user_id=user_in_db.id,
                firstname=user_update.firstname,
                lastname=user_update.lastname,
                address=user_update.address,
                phone_number=user_update.phone_number,
                aboutme=user_update.aboutme,
                bankname=user_update.bankname,
                banknumber=user_update.banknumber
            )
        elif user_update.role == "tutor":
            detail_info = DetailInformation(
                tutor_id=tutor_in_db.id,
                firstname=user_update.firstname,
                lastname=user_update.lastname,
                address=user_update.address,
                phone_number=user_update.phone_number,
                aboutme=user_update.aboutme,
                bankname=user_update.bankname,
                banknumber=user_update.banknumber
            )
        db.add(detail_info)
    
    db.commit()
    db.refresh(detail_info)
    return detail_info


@app.post("/api/upload-avatar")
async def upload_avatar(file: UploadFile = File(...), role: str = Form(...), username: str = Form(...), user: User = Depends(get_current_user)):
    db = next(get_db())
    root = './CV/'
    avatar_filename = f"avatar_{role}_{username}.jpg"
    with open(root + avatar_filename, "wb") as buffer:
        buffer.write(await file.read())

    # Generate a URL with a timestamp
    avatar_url = f"https://speak.id.vn/api/CV/{avatar_filename}?timestamp={int(time.time())}"
    return {"avatar_url": avatar_url}



@app.post("/api/buy-packed")
async def buy_packed(package_id: int, current_user: User = Depends(get_current_user)):
    db = next(get_db())

    # Kiểm tra xem package_id có hợp lệ không
    if package_id not in [1, 2, 3, 4]:
        return {"message": "Gói không hợp lệ"}

    # Lấy thông tin người dùng từ cơ sở dữ liệu
    user = db.query(User).filter(User.username == current_user.username).first()

    # Tạo thông tin mua gói mới
    buy_package = BuyPacked(user_id=user.id, package_id=package_id, status='waiting')

    # Thêm thông tin mua gói vào cơ sở dữ liệu
    db.add(buy_package)
    db.commit()

    return {"message": "Đã mua thành công"}



@app.get("/api/admin/buypacked")
async def get_buy_packed_history(): 
    db = next(get_db())
    buy_packed_history = db.query(BuyPacked, User.username).join(User, User.id == BuyPacked.user_id).all()

    # Tạo một danh sách để lưu trữ thông tin lịch sử mua gói
    result = []

    # Lặp qua mỗi bản ghi trong buy_packed_history và tạo tuple chứa thông tin cần thiết
    for buy_packed, username in buy_packed_history:
        result.append({
            "id": buy_packed.id,
            "username": username,
            "package_id": buy_packed.package_id,
            "purchase_date": buy_packed.purchase_date,
            "status": buy_packed.status
        })

    return result

# @app.post("/user/review")
# def create_review(review: UserReviewCreate, current_user: User = Depends(get_current_user)):
    
#     db = next(get_db())
#     user_in_db = db.query(User).filter(User.username == current_user.username).first()
#     meeting = db.query(Meeting).filter(Meeting.id == review.meeting_id).first()

#     if not meeting or meeting.user_id != user_in_db.id:
#         raise HTTPException(status_code=400, detail="Invalid meeting ID")

#     review_in_db = Review(
#         user_rating=review.user_rating,
#         user_feedback=review.user_feedback,
#         user_suggest=review.user_suggest,  # Add this line
#         tutor_rating=review.tutor_rating,
#         tutor_feedback=review.tutor_feedback,
#         user_id=user_in_db.id,
#         tutor_id=meeting.tutor_id,
#         meeting_id=meeting.id,
#         user_reviewed=True
#     )

#     db.add(review_in_db)
#     db.commit()
#     db.refresh(review_in_db)

#     return review_in_db



@app.get("/api/user/meetings")
def get_meetings(current_user: User = Depends(get_current_user)):
    db = next(get_db())
    user_in_db = db.query(User).filter(User.username == current_user.username).first()
    meetings = db.query(Meeting).join(Tutor, Meeting.tutor_id == Tutor.id).filter(Meeting.user_id == user_in_db.id).all()
    
    meeting_responses = []
    for meeting in meetings:
        review = db.query(Review).filter(Review.meeting_id == meeting.id).first()
        if review:
            meeting_responses.append(UserMeetingResponse(
                id=meeting.id,
                start_time=meeting.start_time.isoformat(),
                tutor_name=meeting.tutor.username,
                user_feedback=review.user_feedback,
                user_rating=review.user_rating,
                tutor_feedback=review.tutor_feedback,
                tutor_rating=review.tutor_rating,
                user_suggest=review.user_suggest,  # Add this line
                tutor_suggest=review.tutor_suggest,  # Add this line
                reviewed=review.user_reviewed,
                topic = meeting.topic
            ))
        else:
            meeting_responses.append(UserMeetingResponse(
                id=meeting.id,
                start_time=meeting.start_time,
                tutor_name=meeting.tutor.username,
                user_feedback=None,
                user_rating=None,
                tutor_feedback=None,
                tutor_rating=None,
                user_suggest=None,  # Add this line
                tutor_suggest=None,  # Add this line
                reviewed=False,
                topic = meeting.topic
            ))
    db.commit()
    print(meeting_responses)
    return meeting_responses


@app.get("/api/admin/meetings", response_model=List[AdminMeetingResponse])
def get_meetings(db: Session = Depends(get_db)):
    meetings = db.query(Meeting).all()
    meeting_responses = []
    for meeting in meetings:
        user = db.query(User).filter(User.id == meeting.user_id).first()
        tutor = db.query(Tutor).filter(Tutor.id == meeting.tutor_id).first()
        review = db.query(Review).filter(Review.meeting_id == meeting.id).first()
        meeting_responses.append(AdminMeetingResponse(
            id=meeting.id,
            link=meeting.link,
            start_time=meeting.start_time,
            user_name=user.username,
            tutor_name=tutor.username,
            user_rating=review.user_rating if review else None,
            user_feedback=review.user_feedback if review else None,
            tutor_rating=review.tutor_rating if review else None,
            tutor_feedback=review.tutor_feedback if review else None,
            user_suggest=review.user_suggest if review else None,
            tutor_suggest=review.tutor_suggest if review else None,
        ))
    return meeting_responses






# @app.post("/tutor/review")
# def create_tutor_review(review: ReviewCreate, current_user: User = Depends(get_current_user)):
#     db: Session = next(get_db())
#     tutor_in_db = db.query(Tutor).filter(Tutor.username == current_user.username).first()
#     meeting = db.query(Meeting).filter(Meeting.id == review.meeting_id).first()

#     if not meeting or meeting.tutor_id != tutor_in_db.id:
#         raise HTTPException(status_code=400, detail="Invalid meeting ID")

#     review_in_db = Review(
#         tutor_rating=review.tutor_rating,
#         tutor_feedback=review.tutor_feedback,
#         tutor_suggest=review.tutor_suggest,
#         user_rating=review.user_rating,
#         user_feedback=review.user_feedback,
#         tutor_id=tutor_in_db.id,
#         user_id=meeting.user_id,
#         meeting_id=meeting.id,
#         tutor_reviewed=True
#     )

#     db.add(review_in_db)
#     db.commit()
#     db.refresh(review_in_db)

#     return review_in_db
# @app.post("/tutor/review")
# def create_review(review: ReviewCreate, current_user: User = Depends(get_current_user)):
#     db = next(get_db())
#     tutor_in_db = db.query(Tutor).filter(Tutor.username == current_user.username).first()
#     meeting = db.query(Meeting).filter(Meeting.id == review.meeting_id).first()

#     if not meeting or meeting.tutor_id != tutor_in_db.id:
#         raise HTTPException(status_code=400, detail="Invalid meeting ID")

#     review_in_db = Review(
#         tutor_rating=review.tutor_rating,
#         tutor_feedback=review.tutor_feedback,
#         tutor_suggest=review.tutor_suggest,  # Add this line
#         user_rating=review.user_rating,
#         user_feedback=review.user_feedback,
#         tutor_id=tutor_in_db.id,
#         user_id=meeting.user_id,
#         meeting_id=meeting.id,
#         tutor_reviewed=True
#     )

#     db.add(review_in_db)
#     db.commit()
#     db.refresh(review_in_db)

#     return review_in_db

# @app.get("/tutor/meetings", response_model=List[MeetingResponse])
# def get_meetings(current_user: User = Depends(get_current_user)):
#     db: Session = next(get_db())
    
#     tutor_in_db = db.query(Tutor).filter(Tutor.username == current_user.username).first()
#     if not tutor_in_db:
#         raise HTTPException(status_code=404, detail="Tutor not found")

#     meetings = db.query(Meeting).join(User, Meeting.user_id == User.id).filter(Meeting.tutor_id == tutor_in_db.id).all()
    
#     meeting_responses = []
#     for meeting in meetings:
#         review = db.query(Review).filter(Review.meeting_id == meeting.id).first()
#         if review:
#             meeting_responses.append(MeetingResponse(
#                 id=meeting.id,
#                 start_time=meeting.start_time,
#                 tutor_name=tutor_in_db.username,  # Ensure tutor_name is correctly set
#                 user_name=meeting.user.username,  # Ensure user_name is correctly set
#                 user_feedback=review.user_feedback,
#                 user_rating=review.user_rating,
#                 tutor_feedback=review.tutor_feedback,
#                 tutor_rating=review.tutor_rating,
#                 user_suggest=review.user_suggest,
#                 tutor_suggest=review.tutor_suggest,
#                 reviewed=review.tutor_reviewed
#             ))
#         else:
#             meeting_responses.append(MeetingResponse(
#                 id=meeting.id,
#                 start_time=meeting.start_time,
#                 tutor_name=tutor_in_db.username,  # Ensure tutor_name is correctly set
#                 user_name=meeting.user.username,  # Ensure user_name is correctly set
#                 user_feedback=None,
#                 user_rating=None,
#                 tutor_feedback=None,
#                 tutor_rating=None,
#                 user_suggest=None,
#                 tutor_suggest=None,
#                 reviewed=False
#             ))
    
#     db.commit()
#     return meeting_responses

# class ConnectionManager:
#     def __init__(self):
#         self.active_connections: Dict[str, WebSocket] = {}
#         self.user_queue = deque()
#         self.tutor_queue = deque()

#     async def connect(self, websocket: WebSocket, user_id: str, user_type: str):
#         await websocket.accept()
#         self.active_connections[user_id] = {"socket": websocket, "type": user_type}
#         if user_type == "user":
#             self.user_queue.append(user_id)
#         elif user_type == "tutor":
#             self.tutor_queue.append(user_id)

#     async def match_users(self):
#         db = get_db()
#         while self.user_queue and self.tutor_queue:
#             user_id = self.user_queue[0]
#             tutor_id = self.tutor_queue[0]
#             user_socket = self.active_connections.get(user_id, {}).get("socket")
#             tutor_socket = self.active_connections.get(tutor_id, {}).get("socket")
#             if user_socket and tutor_socket:
#                 self.user_queue.popleft()
#                 self.tutor_queue.popleft()
#                 redirect_url = f"http://localhost:5000/?id={user_id}/{tutor_id}"
#                 await user_socket.send_json({"redirect_url": redirect_url})
#                 await tutor_socket.send_json({"redirect_url": redirect_url})
#                 # await user_socket.close()  # Close the WebSocket connection
#                 # await tutor_socket.close()
#                 start_time = datetime.now()
#                 end_time = start_time + timedelta(hours=1)
#                 new_meeting = Meeting(
#                     link=redirect_url,
#                     start_time=start_time,
#                     end_time=end_time,
#                     status='upcoming',
#                     user_id=user_id,
#                     tutor_id=tutor_id
#                 )
#                 db.add(new_meeting)
#                 db.commit()

#     def disconnect(self, user_id: str):
#         if user_id in self.active_connections:
#             user_type = self.active_connections[user_id]["type"]
#             del self.active_connections[user_id]
#             if user_type == "user" and user_id in self.user_queue:
#                 self.user_queue.remove(user_id)
#             elif user_type == "tutor" and user_id in self.tutor_queue:
#                 self.tutor_queue.remove(user_id)

# manager = ConnectionManager()

# @app.websocket("/ws/{user_id}/{user_type}")
# async def websocket_endpoint(websocket: WebSocket, user_id: str, user_type: str):
#     current_user = await get_current_user(user_id)
#     if current_user["role"] == "user" and current_user["user"].balance < 0:
#         await websocket.send_json({"message": "Your balance is insufficient"})
#         return
#     await manager.connect(websocket, user_id, user_type)
#     try:
#         while True:
#             data = await websocket.receive_text()
#             token = json.loads(data).get('token')
#             try:
#                 payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#                 username: str = payload.get("sub")
#                 role: str = payload.get("role")
#                 if username is None or role not in ["user", "tutor"]:
#                     raise HTTPException(
#                         status_code=status.HTTP_401_UNAUTHORIZED,
#                         detail="Could not validate credentials",
#                         headers={"WWW-Authenticate": "Bearer"},
#                     )
#                 if username and role:
#                     await manager.match_users()
#             except JWTError:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="Could not validate credentials",
#                     headers={"WWW-Authenticate": "Bearer"},
#                 )
#     except WebSocketDisconnect:
#         manager.disconnect(user_id)

from fastapi import APIRouter, Depends, HTTPException, Path
class CheckPacked(BaseModel):
    payment_id: int
    status: str

@app.put("/api/admin/buypacked/{payment_id}")
async def update_payment_status(payment_id: int, check_packed: CheckPacked):
    db = next(get_db())
    payment = db.query(BuyPacked).filter(BuyPacked.id == payment_id).first()

    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    user = db.query(User).filter(User.id == payment.user_id).first()

    if check_packed.status == 'decline' and payment.status != 'decline':
        user.balance += payment.amount  # Add the amount back to the user's balance if the request is declined

    payment.status = check_packed.status

    # Update package remaining sessions or conversations based on the package ID
    if payment.package_id in [1, 2]:
        package = db.query(Package).filter(Package.user_id == user.id).first()
        package.remaining_learning_sessions += 1 if payment.package_id == 1 else 11
    elif payment.package_id in [3, 4]:
        package = db.query(Package).filter(Package.user_id == user.id).first()
        package.remaining_ai_conversations += 1 if payment.package_id == 3 else 11

    db.commit()

    return {"message": "Payment status updated successfully"}


@app.get("/api/user/buypacked")
async def get_buypacked(user: User = Depends(get_current_user)):
    db = next(get_db())
    username = user.username
    user = db.query(User).filter(User.username == username).first()

    if user is None:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại")

    buypacked = db.query(BuyPacked).filter(BuyPacked.user_id == user.id).all()

    return {"buypacked": [packed.__dict__ for packed in buypacked]}


@app.get("/api/admin/buypacked")
async def get_buy_packed_history(): 
    db = next(get_db())
    buy_packed_history = db.query(BuyPacked, User.username).join(User, User.id == BuyPacked.user_id).all()

    # Tạo một danh sách để lưu trữ thông tin lịch sử mua gói
    result = []

    # Lặp qua mỗi bản ghi trong buy_packed_history và tạo tuple chứa thông tin cần thiết
    for buy_packed, username in buy_packed_history:
        result.append({
            "id": buy_packed.id,
            "username": username,
            "package_id": buy_packed.package_id,
            "purchase_date": buy_packed.purchase_date,
            "status": buy_packed.status
        })

    return result


@app.get("/api/admin/meetings", response_model=List[AdminMeetingResponse])
def get_meetings():
    db = next(get_db())
    meetings = db.query(Meeting).all()
    meeting_responses = []
    for meeting in meetings:
        user = db.query(User).filter(User.id == meeting.user_id).first()
        tutor = db.query(Tutor).filter(Tutor.id == meeting.tutor_id).first()
        review = db.query(Review).filter(Review.meeting_id == meeting.id).first()
        meeting_responses.append(AdminMeetingResponse(
            id=meeting.id,
            link=meeting.link,
            start_time=meeting.start_time,
            user_name=user.username,
            tutor_name=tutor.username,
            user_rating=review.user_rating if review else None,
            user_feedback=review.user_feedback if review else None,
            tutor_rating=review.tutor_rating if review else None,
            tutor_feedback=review.tutor_feedback if review else None,
            user_suggest=review.user_suggest if review else None,
            tutor_suggest=review.tutor_suggest if review else None,
        ))
    return meeting_responses