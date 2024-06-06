from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base

engine = create_engine('sqlite:///./users.db')
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=engine)
