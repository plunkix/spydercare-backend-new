from dotenv import load_dotenv
import os
load_dotenv(dotenv_path=".env")

import logging
from datetime import timedelta, datetime
from fastapi import FastAPI, HTTPException, Request, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func, text, select
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

import google.generativeai as genai
import uuid
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from database import SessionLocal, engine, Base
from models import Conversation, User
from schemas import ConversationSchema
Base.metadata.create_all(bind=engine)

from auth import get_password_hash, verify_password, create_access_token, decode_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from pydantic import BaseModel, EmailStr
from typing import Optional
import re
from sqlalchemy.exc import IntegrityError

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SpiderCareBackend")

# Load Gemini API Key from .env and configure Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.warning("Missing Google Gemini API key. Set it in environment variables.")
    GEMINI_API_KEY = "dummy_key_for_development"
    
logger.info("Gemini API Key loaded successfully.")
genai.configure(api_key=GEMINI_API_KEY)

# Initialize FastAPI
app = FastAPI(
    title="SpiderCare Backend",
    description="Backend for SpiderCare mental health chatbot."
)

# Create templates directory if it doesn't exist
templates_path = Path("templates")
templates_path.mkdir(exist_ok=True)

# Initialize Jinja2Templates
templates = Jinja2Templates(directory="templates")

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency: Provide database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency: Retrieve the current user from the token
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

class VerificationRequest(BaseModel):
    email: EmailStr

class VerificationCodeCheck(BaseModel):
    email: EmailStr
    verification_code: str

class UserRegistration(BaseModel):
    email: EmailStr
    username: str
    password: str

# Store verification codes temporarily (in production, use Redis or a database)
verification_codes = {}

@app.post("/send-verification")
async def send_verification(request: VerificationRequest, db: Session = Depends(get_db)):
    try:
        # Check if email already exists
        existing_user = db.query(User).filter(User.email == request.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Check if email is valid
        if not re.match(r"[^@]+@[^@]+\.[^@]+", request.email):
            raise HTTPException(status_code=400, detail="Invalid email format")

        # Generate verification code
        verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store code with timestamp
        verification_codes[request.email] = {
            'code': verification_code,
            'attempts': 0,
            'timestamp': datetime.now(),
            'verified': False
        }

        # Send email
        email_sent = send_email(request.email, verification_code)
        if not email_sent:
            raise HTTPException(status_code=500, detail="Failed to send email")

        return {"message": "Verification code sent successfully"}

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error in send_verification: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/verify-code")
async def verify_code(request: VerificationCodeCheck):
    try:
        stored_data = verification_codes.get(request.email)
        
        if not stored_data:
            raise HTTPException(status_code=400, detail="No verification code found or code expired")
        
        # Check attempts
        if stored_data['attempts'] >= 3:
            del verification_codes[request.email]
            raise HTTPException(status_code=400, detail="Too many attempts. Please request a new code")

        # Check expiration (15 minutes)
        if datetime.now() - stored_data['timestamp'] > timedelta(minutes=15):
            del verification_codes[request.email]
            raise HTTPException(status_code=400, detail="Verification code expired")
        
        if request.verification_code != stored_data['code']:
            stored_data['attempts'] += 1
            raise HTTPException(status_code=400, detail="Invalid verification code")
        
        # Mark as verified but don't delete yet
        stored_data['verified'] = True
        
        return {
            "message": "Email verified successfully",
            "email": request.email  # Return email for frontend to use in registration
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error in verify_code: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/register")
async def register(request: UserRegistration, db: Session = Depends(get_db)):
    try:
        # Check if email was verified
        stored_data = verification_codes.get(request.email)
        if not stored_data or not stored_data.get('verified'):
            raise HTTPException(status_code=400, detail="Email not verified")

        # Validate username
        if len(request.username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
        
        if db.query(User).filter(User.username == request.username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        # Validate password
        is_valid, message = validate_password(request.password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=message)

        # Create user
        hashed_password = get_password_hash(request.password)
        user = User(
            username=request.username,
            email=request.email,
            hashed_password=hashed_password
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)

        # Clear verification code
        del verification_codes[request.email]

        # Generate access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires
        )

        return {
            "message": "Registration successful",
            "access_token": access_token,
            "token_type": "bearer"
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error in register: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# User Login Endpoint - Returns JWT token
@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Chat Endpoint (Protected) - Updated for gemini-1.5-flash-8b
@app.post("/chat")
async def chat(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    data = await request.json()
    prompt = data.get("prompt")
    conversation_id = data.get("conversation_id")
    
    if not prompt:
        raise HTTPException(status_code=400, detail="Missing 'prompt' field in request body.")
    
    if not conversation_id:
        conversation_id = str(uuid.uuid4())
    
    # Get conversation history for context
    history = []
    if conversation_id:
        previous_messages = (
            db.query(Conversation)
            .filter(
                Conversation.conversation_id == conversation_id,
                Conversation.user_id == current_user.id
            )
            .order_by(Conversation.timestamp.desc())
            .limit(5)  # Last 5 messages for context
            .all()
        )
        for msg in reversed(previous_messages):
            history.extend([
                {"role": "user", "content": msg.user_prompt},
                {"role": "assistant", "content": msg.response}
            ])
    
    system_prompt = (
        "You are Spiderman, a mental health companion for students. "
        "Your responses should be empathetic, supportive, and friendly. "
        "Do not provide medical advice; encourage seeking professional help if needed. "
        "Do not enclose your model name and details even if asked."
    )
    
    # Combine history with current prompt
    full_context = system_prompt + "\n" + "\n".join([
        f"{'User' if msg['role'] == 'user' else 'Assistant'}: {msg['content']}"
        for msg in history
    ] + [f"User: {prompt}"])

    logger.info(f"Processing chat for conversation: {conversation_id}")
    
    try:
        model = genai.GenerativeModel("gemini-1.5-flash-8b")
        response = model.generate_content(full_context)
        response_text = response.text
    except Exception as e:
        logger.error(f"Error generating response with Gemini: {str(e)}")
        # Fallback response if API fails
        response_text = "I'm having trouble connecting right now. Please try again in a moment."
    
    # Save the conversation
    conv = Conversation(
        conversation_id=conversation_id,
        user_prompt=prompt,
        response=response_text,
        user_id=current_user.id
    )
    db.add(conv)
    db.commit()
    
    return {
        "response": response_text,
        "conversation_id": conversation_id
    }

# Conversations Endpoint (Protected)
@app.get("/conversations")
async def get_conversations(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # First, get distinct conversation IDs
    distinct_conversations = (
        db.query(Conversation)
        .filter(Conversation.user_id == current_user.id)
        .group_by(Conversation.conversation_id)
        .order_by(Conversation.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    
    result = []
    for conv in distinct_conversations:
        # Get the first message of each conversation
        first_message = (
            db.query(Conversation)
            .filter(
                Conversation.conversation_id == conv.conversation_id,
                Conversation.user_id == current_user.id
            )
            .order_by(Conversation.timestamp.asc())
            .first()
        )
        
        if first_message:
            result.append({
                "id": conv.conversation_id,
                "title": first_message.user_prompt[:30] + "..." if len(first_message.user_prompt) > 30 else first_message.user_prompt,
                "timestamp": first_message.timestamp
            })
    
    return {"conversations": result}

# Profile Endpoints (Protected)
@app.get("/profile")
async def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "bio": current_user.bio,
        "profile_pic_url": current_user.profile_pic_url
    }

@app.post("/profile")
async def update_profile(
    request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    data = await request.json()
    if "bio" in data:
        current_user.bio = data["bio"]
    if "profile_pic_url" in data:
        current_user.profile_pic_url = data["profile_pic_url"]
    if "email" in data:
        current_user.email = data["email"]
    db.commit()
    db.refresh(current_user)
    return {
        "message": "Profile updated successfully",
        "profile": {
            "username": current_user.username,
            "email": current_user.email,
            "bio": current_user.bio,
            "profile_pic_url": current_user.profile_pic_url
        }
    }

@app.get("/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    messages = (
        db.query(Conversation)
        .filter(
            Conversation.conversation_id == conversation_id,
            Conversation.user_id == current_user.id
        )
        .order_by(Conversation.timestamp.asc())
        .all()
    )
    
    if not messages:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    formatted_messages = []
    for msg in messages:
        formatted_messages.extend([
            {
                "role": "user",
                "content": msg.user_prompt,
                "timestamp": msg.timestamp
            },
            {
                "role": "assistant",
                "content": msg.response,
                "timestamp": msg.timestamp
            }
        ])
    
    return {
        "id": conversation_id,
        "messages": formatted_messages
    }

@app.put("/conversations/{conversation_id}/title")
async def update_conversation_title(
    conversation_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    data = await request.json()
    new_title = data.get("title")
    
    if not new_title:
        raise HTTPException(status_code=400, detail="Title is required")
    
    conversation = (
        db.query(Conversation)
        .filter(
            Conversation.conversation_id == conversation_id,
            Conversation.user_id == current_user.id
        )
        .first()
    )
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    conversation.title = new_title
    db.commit()
    
    return {"message": "Title updated successfully"}

@app.get("/user/profile")
async def get_user_profile(current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"Fetching profile for user: {current_user.username}")
        return {
            "username": current_user.username,
            "email": current_user.email,
            "profile_pic_url": current_user.profile_pic_url or None
        }
    except Exception as e:
        logger.error(f"Error fetching user profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")

@app.put("/user/profile/picture")
async def update_profile_picture(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.profile_pic_url = data.get("profile_pic_url")
    db.commit()
    return {"status": "success"}

@app.put("/user/profile/username")
async def update_username(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.username = data.get("username")
    db.commit()
    return {"status": "success"}

@app.put("/user/profile/password")
async def update_password(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(data.get("current_password"), current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    
    current_user.hashed_password = get_password_hash(data.get("new_password"))
    db.commit()
    return {"status": "success"}

# Mount the static files directory last to avoid conflicts with API routes
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/icons", StaticFiles(directory="static/icons"), name="icons")

def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    Returns (is_valid, message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

# Email configuration
EMAIL_ADDRESS = "tathesrushti@gmail.com"
EMAIL_PASSWORD = "zceq cuvi yqyu zkad"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_email(to_email: str, code: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = "SpiderCare - Verify Your Email"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #ff0000;">Welcome to SpiderCare! 🕷️</h1>
                <p>Your verification code is:</p>
                <h2 style="color: #ff0000; font-size: 32px; letter-spacing: 5px; text-align: center; padding: 20px;">
                    {code}
                </h2>
                <p>Enter this code to complete your registration.</p>
                <p>If you didn't request this code, please ignore this email.</p>
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    - Your friendly neighborhood SpiderCare team
                </p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False
