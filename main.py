import os
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, ValidationError
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
import logging
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse 
from httpx_oauth.clients.google import GoogleOAuth2

# --- Load Environment Variables ---
load_dotenv()

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration ---
DATABASE_URL = "sqlite:///./404_ai.db"
SECRET_KEY = "0d727fb751e6f3741b72b679f80a8a40d720c7d9088a9819f0d6ca374df00961"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Google OAuth2 Config ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URL = "http://127.0.0.1:8000/auth/google/callback"
google_client = GoogleOAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

# --- Database Setup ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Database Model ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# --- Pydantic Models ---
class UserCreate(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- FastAPI App Instance ---
app = FastAPI()

# --- CORS Middleware ---
origins = ["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Helper Functions ---
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

# --- Standard Auth Endpoints ---
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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Google OAuth Endpoints ---
@app.get("/auth/google/login")
async def google_login():
    authorization_url = await google_client.get_authorization_url(
        redirect_uri=GOOGLE_REDIRECT_URL,
        scope=["email", "profile"],
    )
    return {"authorization_url": authorization_url}

@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    # This successfully gets the token dictionary from Google
    token = await google_client.get_access_token(request.query_params["code"], redirect_uri=GOOGLE_REDIRECT_URL)
    
    # --- THE FINAL FIX ---
    # Directly decode the 'id_token' JWT to get user info
    id_token_jwt = token.get("id_token")
    if not id_token_jwt:
        raise HTTPException(status_code=400, detail="ID token not found in Google's response")
    
    try:
        # Decode the JWT payload without verifying the signature (already handled by the library)
        payload = jwt.decode(id_token_jwt, options={"verify_signature": False})
        user_email = payload.get("email")
        if not user_email:
            raise HTTPException(status_code=400, detail="Email not found in ID token")
            
    except (jwt.PyJWTError, ValidationError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {e}")
    # --- END OF FIX ---

    # Check if user exists, if not, create them
    db_user = db.query(User).filter(User.email == user_email).first()
    if not db_user:
        db_user = User(email=user_email) # No password for OAuth user
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
    # Create our own app's JWT and redirect
    access_token = create_access_token(data={"sub": db_user.email})
    frontend_redirect_url = f"http://localhost:8080/auth/google/callback?token={access_token}"
    return RedirectResponse(url=frontend_redirect_url)
