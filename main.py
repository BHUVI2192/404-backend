import os
import jwt
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from dotenv import load_dotenv
from httpx_oauth.clients.google import GoogleOAuth2
import google.generativeai as genai

# --- ENV and CORE DB ---
load_dotenv()
DATABASE_URL = "postgresql://404-ai:404%409988@localhost:5432/the-404-ai"
SECRET_KEY = os.getenv("SECRET_KEY", "set-a-real-prod-secret-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

gemini_api_key = os.getenv("GEMINI_API_KEY", None)
if gemini_api_key:
    genai.configure(api_key=gemini_api_key)
    GEMINI_MODEL = genai.GenerativeModel('gemini-pro-latest')
else:
    GEMINI_MODEL = None
    logging.warning("GEMINI_API_KEY not found.")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URL = "http://127.0.0.1:8000/auth/google/callback"
google_client = GoogleOAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- SQLAlchemy Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=True)

class SessionModel(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String, default="New Chat")
    start_time = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    memory_entries = relationship("MemoryEntry", back_populates="session")
    user = relationship("User", back_populates="sessions")

User.sessions = relationship("SessionModel", order_by=SessionModel.id, back_populates="user")

class MemoryEntry(Base):
    __tablename__ = "memory_entries"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    tags = Column(String, nullable=True)
    topic = Column(String, nullable=True)
    session = relationship("SessionModel", back_populates="memory_entries")
    user = relationship("User")

Base.metadata.create_all(bind=engine)

# --- Pydantic Schemas ---
class ChatRequest(BaseModel):
    prompt: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    email: str
    password: str

class MemoryEntryOut(BaseModel):
    id: int
    prompt: str
    response: str
    timestamp: datetime
    tags: Optional[str]
    topic: Optional[str]
    session_id: int
    class Config:
        orm_mode = True

class SessionOut(BaseModel):
    id: int
    title: str
    start_time: datetime
    last_updated: datetime
    class Config:
        orm_mode = True

# --- Security Utilities ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password[:72], hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password[:72])

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
        if email is None:
            raise credentials_exception
    except (jwt.PyJWTError, ValidationError):
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- FastAPI App & Routes ---
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/")
def root():
    return {"status": "running", "message": "404 AI backend API is alive!"}

@app.get("/.well-known/appspecific/com.chrome.devtools.json")
def chrome_devtools():
    return JSONResponse(content={"message": "No app-specific configuration available."})

def route_prompt_to_model(prompt: str):
    prompt_lower = prompt.lower()
    if any(keyword in prompt_lower for keyword in ["image", "draw", "picture", "visual"]):
        return "image_generation_placeholder"
    return "gemini_pro"

@app.post("/api/v1/chat/route")
async def handle_chat_request(
    chat_request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    model_choice = route_prompt_to_model(chat_request.prompt)
    if not GEMINI_MODEL:
        raise HTTPException(status_code=503, detail="AI Service is not configured.")

    # Create new session or you can modify logic to reuse session based on your frontend
    session = SessionModel(user_id=current_user.id, start_time=datetime.utcnow(), title="New Chat")
    db.add(session)
    db.commit()
    db.refresh(session)

    try:
        if model_choice == "image_generation_placeholder":
            response_text = f"Image generation for '{chat_request.prompt}' is coming soon!"
        else:
            response = GEMINI_MODEL.generate_content(chat_request.prompt)
            response_text = response.text
    except Exception as e:
        logging.error(f"Error calling AI model {model_choice}: {e}")
        raise HTTPException(status_code=500, detail="AI model error.")

    memory_entry = MemoryEntry(
        user_id=current_user.id,
        session_id=session.id,
        prompt=chat_request.prompt,
        response=response_text,
        timestamp=datetime.utcnow(),
    )
    db.add(memory_entry)
    session.last_updated = datetime.utcnow()
    db.commit()

    return {"response": response_text, "model_used": model_choice}

@app.get("/api/v1/memory/", response_model=List[MemoryEntryOut])
def get_user_memory(
    session_id: Optional[int] = Query(None, description="Optional session filter"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(MemoryEntry).filter(MemoryEntry.user_id == current_user.id)
    if session_id:
        query = query.filter(MemoryEntry.session_id == session_id)
    entries = query.order_by(MemoryEntry.timestamp.desc()).all()
    return entries

@app.get("/api/v1/sessions/", response_model=List[SessionOut])
def get_user_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == current_user.id)
        .order_by(SessionModel.last_updated.desc())
        .all()
    )
    return sessions

@app.post("/api/v1/register", response_model=Token)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

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
    if not id_token_jwt:
        raise HTTPException(status_code=400, detail="ID token not found")
    try:
        payload = jwt.decode(id_token_jwt, options={"verify_signature": False})
        user_email = payload.get("email")
        if not user_email:
            raise HTTPException(status_code=400, detail="Email not found in ID token")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {e}")
    db_user = db.query(User).filter(User.email == user_email).first()
    if not db_user:
        db_user = User(email=user_email)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    access_token = create_access_token(data={"sub": db_user.email})
    frontend_redirect_url = f"http://localhost:8080/auth/google/callback?token={access_token}"
    return RedirectResponse(url=frontend_redirect_url)

Base.metadata.create_all(bind=engine)
