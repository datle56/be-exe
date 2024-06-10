from pydantic import BaseModel
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class PaymentOut(BaseModel):
    id: int
    amount: int
    timestamp: Optional[datetime]
    user_id: int
    status: str
    
class PaymentCreate(BaseModel):
    amount: int
    user_id: int
    status: str

class TutorReviewCreate(BaseModel):
    meeting_id: int
    tutor_rating: Optional[int] = None
    tutor_feedback: Optional[str] = None
    tutor_suggest: Optional[str] = None


class AdminMeetingResponse(BaseModel):
    id: int
    link: str
    start_time: datetime
    user_name: str
    tutor_name: str
    user_rating: Optional[int] = None
    user_feedback: Optional[str] = None
    tutor_rating: Optional[int] = None
    tutor_feedback: Optional[str] = None
    user_suggest: Optional[str] = None
    tutor_suggest: Optional[str] = None

    class Config:
        orm_mode = True


class EarningsHistory(BaseModel):
    id: int
    date: datetime
    username: str
    topic: str
    base_earnings: int
    bonus_type: str

    class Config:
        orm_mode = True