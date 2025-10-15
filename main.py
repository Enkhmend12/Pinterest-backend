
# main.py - Updated with password truncation fix - FORCE REDEPLOY

import os
import sys
import random
import requests
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Iterator
from passlib.context import CryptContext

from sqlalchemy import create_engine, Column, Integer, String, text, DateTime, Boolean
from sqlalchemy.orm import sessionmaker,  Session
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv()

# Config via environment (set these in Railway/host or a .env file locally)
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-change")

# Email configuration with Resend
RESEND_API_KEY = os.getenv("RESEND_API_KEY")  # Your Resend API key

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
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

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

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str

# ---- Payment Cards ----
class PaymentCard(Base):
    __tablename__ = "payment_cards"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)  # owner by email for simplicity
    company = Column(String, nullable=False)
    amount_tug = Column(Integer, nullable=False)  # store in smallest unit (₮)
    image_url = Column(String, nullable=True)
    isPaid = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=text('NOW()'))

class PaymentCardCreate(BaseModel):
    email: str
    company: str
    amount_tug: int
    image_url: str | None = None
    isPaid: bool

class PaymentCardOut(BaseModel):
    id: int
    email: str
    company: str
    amount_tug: int
    image_url: str | None
    isPaid: bool
    created_at: datetime | None = None

    class Config:
        from_attributes = True

# Email sending function with Resend
def send_verification_email(email: str, code: str):
    """Send verification code via email using Resend"""
    try:
        if not RESEND_API_KEY:
            return False
            
        # Resend API endpoint
        url = "https://api.resend.com/emails"
        
        # Email data
        email_data = {
            "from": "Pinterest <onboarding@resend.dev>",  # Resend's testing sender
            "to": [email],
            "subject": "Pinterest - Email Verification Code",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #E60023; margin: 0;">Pinterest</h1>
                </div>
                
                <h2 style="color: #333; margin-bottom: 20px;">Welcome to Pinterest!</h2>
                
                <p style="color: #555; font-size: 16px; line-height: 1.5;">
                    Please use the following verification code to complete your account setup:
                </p>
                
                <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0;">
                    <div style="font-size: 32px; font-weight: bold; color: #E60023; letter-spacing: 5px;">
                        {code}
                    </div>
                </div>
                
                <p style="color: #666; font-size: 14px;">
                    This code will expire in <strong>10 minutes</strong> for your security.
                </p>
                
                <p style="color: #666; font-size: 14px;">
                    If you didn't create a Pinterest account, please ignore this email.
                </p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                
                <p style="color: #999; font-size: 12px; text-align: center;">
                    This is an automated message from Pinterest. Please do not reply to this email.
                </p>
            </div>
            """
        }
        
        # Send request to Resend
        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(url, json=email_data, headers=headers)
        
        if response.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
        return False

# Email sending function for password reset
def send_password_reset_email(email: str, code: str):
    """Send password reset code via email using Resend"""
    try:
        if not RESEND_API_KEY:
            return False
            
        # Resend API endpoint
        url = "https://api.resend.com/emails"
        
        # Email data
        email_data = {
            "from": "Pinterest <onboarding@resend.dev>",  # Resend's testing sender
            "to": [email],
            "subject": "Pinterest - Password Reset Code",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #E60023; margin: 0;">Pinterest</h1>
                </div>
                
                <h2 style="color: #333; margin-bottom: 20px;">Reset Your Password</h2>
                
                <p style="color: #555; font-size: 16px; line-height: 1.5;">
                    You requested to reset your password. Use the following code to create a new password:
                </p>
                
                <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0;">
                    <div style="font-size: 32px; font-weight: bold; color: #E60023; letter-spacing: 5px;">
                        {code}
                    </div>
                </div>
                
                <p style="color: #666; font-size: 14px;">
                    This code will expire in <strong>10 minutes</strong> for your security.
                </p>
                
                <p style="color: #666; font-size: 14px;">
                    If you didn't request a password reset, please ignore this email.
                </p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                
                <p style="color: #999; font-size: 12px; text-align: center;">
                    This is an automated message from Pinterest. Please do not reply to this email.
                </p>
            </div>
            """
        }
        
        # Send request to Resend
        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(url, json=email_data, headers=headers)
        
        if response.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
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
        # Hash the password (truncate to 72 bytes for bcrypt compatibility)
        password = user_data.password
        
        if len(password.encode('utf-8')) > 72:
            # Truncate to 72 bytes, not characters
            print(f"Password is longer than 72 bytes, truncating...")
            password_bytes = password.encode('utf-8')[:72]
            password = password_bytes.decode('utf-8', errors='ignore')
            print(f"Truncated password: {password}")
        else:
            print(f"Password is within 72 bytes, no truncation needed")
            
        hashed_password = pwd_context.hash(password)
        
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

# API endpoint to request password reset
@app.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Sends a password reset code to the user's email.
    """
    try:
        email = request.email
        
        # Check if user exists
        user = db.query(User).filter(User.email == email).first()
        if not user:
            # For testing: still send email even if user doesn't exist
            # In production, you might want to return the generic message
            pass
        
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
        
        # Send password reset email
        email_sent = send_password_reset_email(email, code)
        
        if email_sent:
            return {
                "message": "Password reset code sent to your email!",
                "code": code,  # Remove this in production!
                "expires_in_minutes": 10
            }
        else:
            return {
                "message": "Password reset code generated (email service unavailable)",
                "code": code,  # For testing purposes
                "expires_in_minutes": 10
            }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error sending password reset code: {e}")

# API endpoint to reset password with verification code
@app.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Resets the user's password using the verification code.
    """
    try:
        email = request.email
        code = request.code
        new_password = request.new_password
        
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
        
        # Find the user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Hash the new password (truncate to 72 bytes for bcrypt compatibility)
        password = new_password



        if len(password.encode('utf-8')) > 72:
            # Truncate to 72 bytes, not characters
            password_bytes = password.encode('utf-8')[:72]
            password = password_bytes.decode('utf-8', errors='ignore')
        hashed_password = pwd_context.hash(password)
        
        # Update user's password
        user.hashed_password = hashed_password
        db.commit()
        
        # Mark verification code as used
        verification_record.is_used = "true"
        db.commit()
        
        return {
            "message": "Password reset successfully!",
            "success": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error resetting password: {e}")

# ---- Payment Card Endpoints ----
@app.get("/payment-cards", response_model=list[PaymentCardOut])
def list_payment_cards(email: str, db: Session = Depends(get_db)):
    try:
        cards = db.query(PaymentCard).filter(PaymentCard.email == email).order_by(PaymentCard.id.desc()).all()
        return cards
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching cards: {e}")

@app.post("/payment-cards", response_model=PaymentCardOut, status_code=201)
def create_payment_card(card: PaymentCardCreate, db: Session = Depends(get_db)):
    try:
        new_card = PaymentCard(
            email=card.email,
            company=card.company,
            amount_tug=card.amount_tug,
            image_url=card.image_url,
            isPaid = card.isPaid,
        )
        db.add(new_card)
        db.commit()
        db.refresh(new_card)
        return new_card
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Error creating card: {e}")
