
# main.py

import os
import sys
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Iterator
from passlib.context import CryptContext

from sqlalchemy import create_engine, Column, Integer, String, text
from sqlalchemy.orm import sessionmaker,  Session
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv()

# Config via environment (set these in Railway/host or a .env file locally)
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-change")

# Ensure the database URL is set
if not DATABASE_URL:
    print("Error: DATABASE_URL environment variable is not set.")
    sys.exit(1)

# Create the SQLAlchemy engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Create a session local class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a declarative base
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define the user data model for the database table
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=False)

# Create all tables in the database
Base.metadata.create_all(bind=engine)

# Define the data model for the incoming request
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# Dependency to get a new database session for each request
def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize the FastAPI application
app = FastAPI()

# CORS: allow the Flutter app (and later your domain) to call this API from the browser/app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace with your domain(s) in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple health endpoint to verify service and DB connectivity
@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"unhealthy: {e}")

# API endpoint to create a new user with email and password
@app.post("/users/", status_code=status.HTTP_201_CREATED)
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Receives an email and password, hashes the password, and saves to the 'users' table.
    """
    try:
        # Hash the password
        hashed_password = pwd_context.hash(user_data.password)
        
        # Create user with hashed password
        new_user = User(email=user_data.email, hashed_password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"message": "User created successfully!", "user": {"id": new_user.id, "email": new_user.email}}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Error saving user: {e}")

# API endpoint to login user
@app.post("/auth/login", status_code=status.HTTP_200_OK)
def login_user(user_data: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates user by checking email and password.
    """
    try:
        # Find user by email
        user = db.query(User).filter(User.email == user_data.email).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password
        if not pwd_context.verify(user_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Login successful
        return {
            "message": "Login successful!",
            "user": {
                "id": user.id,
                "email": user.email
            }
        }
    
    except HTTPException:
        # Re-raise HTTP exceptions (like 401 Unauthorized)
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
