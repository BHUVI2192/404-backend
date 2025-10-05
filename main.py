import os
import jwt
import logging
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from dotenv import load_dotenv
from httpx_oauth.clients.google import GoogleOAuth2

# AI Model Import
import google.generativeai as genai

# Load Environment Variables
load_dotenv()

# --- Configuration ---
DATABASE_URL = "sqlite:///./404_ai.db"
SECRET_KEY = "0d727fb751e6f3741b72b679f80a8a40d720c7d9088a9819f0d6ca374df00961"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- AI Model Configuration (Free Tier) ---
try:
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if gemini_api_key:
        genai.configure(api_key=gemini_api_key)
        # --- THE FINAL FIX: Using the 'latest' tag for automatic versioning ---
        GEMINI_MODEL = genai.GenerativeModel('gemini-pro-latest')
    else:
        GEMINI_MODEL = None
        logging.warning("GEMINI_API_KEY not found. AI features will be limited.")
except Exception as e:
    GEMINI_MODEL = None
    logging.error(f"AI Model configuration failed: {e}")

# --- Google OAuth2 Config ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URL = "http://127.0.0.1:8000/auth/google/callback"
google_client = GoogleOAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

# --- Database Setup ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# --- Pydantic Models ---
class ChatRequest(BaseModel): prompt: str
class Token(BaseModel): access_token: str; token_type: str
class UserCreate(BaseModel): email: str; password: str

# --- Security & Dependencies ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def verify_password(plain_password, hashed_password):
    if not hashed_password: return False
    return pwd_context.verify(plain_password[:72].encode('utf-8'), hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password[:72].encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except (jwt.PyJWTError, ValidationError):
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise credentials_exception
    return user

# --- FastAPI App & CORS ---
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- AI Orchestration Logic ---
def route_prompt_to_model(prompt: str):
    prompt_lower = prompt.lower()
    if any(keyword in prompt_lower for keyword in ["image", "draw", "picture", "visual"]):
        return "image_generation_placeholder"
    return "gemini_pro"

# --- API Endpoints ---

# Chat Endpoint
@app.post("/api/v1/chat/route")
async def handle_chat_request(chat_request: ChatRequest, current_user: User = Depends(get_current_user)):
    model_choice = route_prompt_to_model(chat_request.prompt)
    response_text = ""
    if not GEMINI_MODEL:
        raise HTTPException(status_code=503, detail="AI Service is not configured.")
    try:
        if model_choice == "image_generation_placeholder":
            response_text = f"Image generation for '{chat_request.prompt}' is coming soon!"
        else:
            response = GEMINI_MODEL.generate_content(chat_request.prompt)
            response_text = response.text
    except Exception as e:
        logging.error(f"Error calling AI model {model_choice}: {e}")
        raise HTTPException(status_code=500, detail="AI model error.")
    return {"response": response_text, "model_used": model_choice}

# Standard Auth Endpoints
@app.post("/api/v1/register", response_model=Token)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user: raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user); db.commit(); db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Google OAuth Endpoints
@app.get("/auth/google/login")
async def google_login():
    authorization_url = await google_client.get_authorization_url(
        redirect_uri=GOOGLE_REDIRECT_URL,
        scope=["email", "profile"],
    )
    return {"authorization_url": authorization_url}

@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await google_client.get_access_token(request.query_params["code"], redirect_uri=GOOGLE_REDIRECT_URL)
    id_token_jwt = token.get("id_token")
    if not id_token_jwt: raise HTTPException(status_code=400, detail="ID token not found")
    try:
        payload = jwt.decode(id_token_jwt, options={"verify_signature": False})
        user_email = payload.get("email")
        if not user_email: raise HTTPException(status_code=400, detail="Email not found in ID token")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {e}")
    db_user = db.query(User).filter(User.email == user_email).first()
    if not db_user:
        db_user = User(email=user_email)
        db.add(db_user); db.commit(); db.refresh(db_user)
    access_token = create_access_token(data={"sub": db_user.email})
    frontend_redirect_url = f"http://localhost:8080/auth/google/callback?token={access_token}"
    return RedirectResponse(url=frontend_redirect_url)
