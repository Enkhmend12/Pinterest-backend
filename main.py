
# main.py

import os
import sys
import random
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Iterator
from passlib.context import CryptContext

from sqlalchemy import create_engine, Column, Integer, String, text, DateTime
from sqlalchemy.orm import sessionmaker,  Session
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv()

# Config via environment (set these in Railway/host or a .env file locally)
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-change")

# Email configuration
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER")  # Your Gmail address
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  # Your Gmail app password

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

# Define the email verification code model
class EmailVerificationCode(Base):
    __tablename__ = "email_verification_codes"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(String, default="false")  # Using string for SQLite compatibility

# Create all tables in the database
Base.metadata.create_all(bind=engine)

# Define the data model for the incoming request
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class EmailVerificationRequest(BaseModel):
    email: str

class VerifyCodeRequest(BaseModel):
    email: str
    code: str

# Email sending function
def send_verification_email(email: str, code: str):
    """Send verification code via email"""
    try:
        if not EMAIL_USER or not EMAIL_PASSWORD:
            print("Warning: Email credentials not configured")
            return False
            
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        msg['Subject'] = "Pinterest - Email Verification Code"
        
        # Email body
        body = f"""
        Hi there!
        
        Your Pinterest verification code is: {code}
        
        This code will expire in 10 minutes.
        
        If you didn't request this code, please ignore this email.
        
        Best regards,
        Pinterest Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"Verification email sent to {email}")
        return True
        
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# Generate random verification code
def generate_verification_code():
    """Generate a 6-digit verification code"""
    return str(random.randint(100000, 999999))

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

# API endpoint to check if email exists in database
@app.post("/check-email", status_code=status.HTTP_200_OK)
def check_email_exists(user_data: dict, db: Session = Depends(get_db)):
    """
    Checks if an email already exists in the database.
    """
    try:
        email = user_data.get('email')
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        
        # Check if user exists
        existing_user = db.query(User).filter(User.email == email).first()
        
        return {
            "exists": existing_user is not None,
            "message": "Email checked successfully"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking email: {e}")

# API endpoint to send verification code
@app.post("/send-verification-code", status_code=status.HTTP_200_OK)
def send_verification_code(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    """
    Generates and sends a verification code to the email address.
    """
    try:
        email = request.email
        
        # Generate verification code
        code = generate_verification_code()
        expires_at = datetime.now() + timedelta(minutes=10)
        
        # Delete any existing codes for this email
        db.query(EmailVerificationCode).filter(EmailVerificationCode.email == email).delete()
        
        # Save new code to database
        verification_record = EmailVerificationCode(
            email=email,
            code=code,
            expires_at=expires_at,
            is_used="false"
        )
        db.add(verification_record)
        db.commit()
        
        # Send email (for development, we'll also return the code in response)
        email_sent = send_verification_email(email, code)
        
        if email_sent:
            return {
                "message": "Verification code sent successfully!",
                "code": code,  # Remove this in production!
                "expires_in_minutes": 10
            }
        else:
            # If email sending fails, still return success but with the code for testing
            return {
                "message": "Verification code generated (email service unavailable)",
                "code": code,  # For testing purposes
                "expires_in_minutes": 10
            }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error sending verification code: {e}")

# API endpoint to verify the code
@app.post("/verify-code", status_code=status.HTTP_200_OK)
def verify_code(request: VerifyCodeRequest, db: Session = Depends(get_db)):
    """
    Verifies the email verification code.
    """
    try:
        email = request.email
        code = request.code
        
        # Find the verification record
        verification_record = db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.code == code,
            EmailVerificationCode.is_used == "false"
        ).first()
        
        if not verification_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code"
            )
        
        # Check if code has expired
        if datetime.now() > verification_record.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code has expired"
            )
        
        # Mark code as used
        verification_record.is_used = "true"
        db.commit()
        
        return {
            "message": "Email verified successfully!",
            "verified": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verifying code: {e}")
