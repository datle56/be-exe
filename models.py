from sqlalchemy import Column, Integer, String, ForeignKey,Text,Boolean, DateTime, Date, Time,Float
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timedelta
from sqlalchemy import Enum
from sqlalchemy.sql import func
from sqlalchemy import CheckConstraint

Base = declarative_base()
from pydantic import BaseModel
from typing import Optional
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    balance = Column(Integer, default=0)

    online_status = Column(Enum('online', 'offline'), default='offline')
    last_login = Column(DateTime(timezone=True), default=func.now())

    

class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    remaining_learning_sessions = Column(Integer, default=0)
    remaining_ai_conversations = Column(Integer, default=0)
    purchase_date = Column(DateTime(timezone=True), default=func.now())

class Tutor(Base):
    __tablename__ = "tutors"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    balance = Column(Integer, default=0)
    status = Column(Enum('waiting', 'accept', 'decline'), default = 'waiting')

    online_status = Column(Enum('online', 'offline'), default='offline')
    last_login = Column(DateTime(timezone=True), default=func.now())
    earnings_history = relationship("TutorEarningsHistory", back_populates="tutor")







class DailyTeachingTime(Base):
    __tablename__ = "daily_teaching_times"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    date = Column(Date)
    teaching_slot = Column(Integer)
    tutor_id = Column(Integer, ForeignKey('tutors.id'))

class DetailInformation(Base):
    __tablename__ = "detail_information"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    firstname = Column(String)
    lastname = Column(String)
    address = Column(String)
    phone_number = Column(String)
    aboutme = Column(String)
    bankname = Column(String)
    banknumber = Column(String)

class BuyPacked(Base):
    __tablename__ = "buypacked"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    package_id = Column(Integer, ForeignKey('packages.id'))
    purchase_date = Column(DateTime(timezone=True), default=func.now())
    status = Column(Enum('waiting', 'accept', 'decline'))

class CVHistory(Base):
    __tablename__ = "cv_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    status = Column(Enum('waiting', 'accept', 'decline'))
    submit_time = Column(DateTime, default=datetime.utcnow)

class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String, index=True)
    description = Column(Text)
    tutor_id = Column(Integer, ForeignKey('tutors.id'))

    tutor = relationship("Tutor", back_populates="courses")

Tutor.courses = relationship("Course", back_populates="tutor")





class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    amount = Column(Integer)
    timestamp = Column(DateTime)
    user_id = Column(Integer, ForeignKey('users.id'))
    status = Column(Enum('waiting', 'accept', 'decline')) 
    transaction_type = Column(Enum('withdraw', 'deposit'))
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    
class History(Base):
    __tablename__ = "histories"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action = Column(String)
    timestamp = Column(DateTime)
    user_id = Column(Integer, ForeignKey('users.id'))
    note = Column(String)  # new field


class Availability(Base):
    __tablename__ = "availabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    date = Column(Date)
    start_time = Column(Time)
    end_time = Column(Time)
    tutor_id = Column(Integer, ForeignKey('tutors.id'))

class Booking(Base):
    __tablename__ = "bookings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    date = Column(Date)
    start_time = Column(Time)
    end_time = Column(Time)
    user_id = Column(Integer, ForeignKey('users.id'))
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    duration = Column(Integer)

class DailyLearningTime(Base):
    __tablename__ = "daily_learning_times"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    date = Column(Date)
    learning_time = Column(Integer)
    user_id = Column(Integer, ForeignKey('users.id'))



class Review(Base):
    __tablename__ = "reviews"

    meeting_id = Column(Integer, ForeignKey('meetings.id'), primary_key=True)
    user_rating = Column(Integer, CheckConstraint('user_rating>=1 AND user_rating<=5'))
    tutor_rating = Column(Integer, CheckConstraint('tutor_rating>=1 AND tutor_rating<=5'))
    user_feedback = Column(String)
    tutor_feedback = Column(String)
    user_suggest = Column(String)
    tutor_suggest = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    user_reviewed = Column(Boolean, default=False)
    tutor_reviewed = Column(Boolean, default=False)
    meeting = relationship("Meeting", back_populates="reviews")


class Meeting(Base):
    __tablename__ = "meetings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    link = Column(String)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    status = Column(Enum('upcoming', 'ongoing', 'completed'))
    user_id = Column(Integer, ForeignKey('users.id'))
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    topic = Column(String)  # Thêm cột này
    tutor = relationship("Tutor")
    user = relationship("User")
    reviews = relationship("Review", back_populates="meeting")
    earnings_history = relationship("TutorEarningsHistory", back_populates="session")


class TutorEarningsHistory(Base):
    __tablename__ = "tutor_earnings_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    tutor_id = Column(Integer, ForeignKey('tutors.id'))
    date = Column(Date, default=func.current_date())
    session_id = Column(Integer, ForeignKey('meetings.id'), nullable=True)
    base_earnings = Column(Integer, default=0)
    bonus_type = Column(String, nullable=True)  # Add this column to record the type of bonus
    total_earnings = Column(Integer, default=0)

    tutor = relationship("Tutor", back_populates="earnings_history")
    session = relationship("Meeting", back_populates="earnings_history")

