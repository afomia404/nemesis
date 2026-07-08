from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional, List
import os
import sqlite3
import json
from ai_logic import generate_threat_analysis

# ---------- CONFIG ----------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="NEMESIS AI Security Engine")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- PASSWORD HASHING ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# ---------- DATABASE ----------
def init_db():
    conn = sqlite3.connect("nemesis.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_url TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            ai_analysis TEXT,
            execution_payload TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- MODELS ----------
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None

class SimulationRequest(BaseModel):
    target_url: str
    vuln_type: str

class SimulationResponse(BaseModel):
    target_url: str
    vuln_type: str
    ai_analysis: str
    execution_payload: str
    status: str

class ScanHistory(BaseModel):
    id: int
    target_url: str
    vuln_type: str
    ai_analysis: str
    execution_payload: str
    status: str
    created_at: datetime

# ---------- HELPER FUNCTIONS ----------
def get_db():
    conn = sqlite3.connect("nemesis.db")
    conn.row_factory = sqlite3.Row
    return conn

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if user is None:
        raise credentials_exception
    return dict(user)

# ---------- AUTH ENDPOINTS ----------
@app.post("/auth/register", response_model=UserOut)
def register(user: UserCreate):
    conn = get_db()
    existing = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", 
                           (user.username, user.email)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    hashed_password = get_password_hash(user.password)
    cursor = conn.execute(
        "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
        (user.username, user.email, hashed_password)
    )
    conn.commit()
    user_data = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    conn.close()
    return dict(user_data)

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (form_data.username,)).fetchone()
    conn.close()
    
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer", "username": user["username"]}

@app.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {"id": current_user["id"], "username": current_user["username"], "email": current_user["email"]}

# ---------- PROTECTED API ENDPOINTS ----------
@app.post("/api/v1/simulate", response_model=SimulationResponse)
def run_simulation(
    request: SimulationRequest,
    current_user: dict = Depends(get_current_user)
):
    # 1. Run AI analysis
    ai_analysis = generate_threat_analysis(request.target_url, request.vuln_type)
    
    # 2. Generate payload
    if request.vuln_type == "Broken Access Control":
        payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZW1wbG95ZWVfNzciLCJyb2xlIjoiYWRtaW4ifQ"
    elif request.vuln_type == "SQL Injection":
        payload = "admin' OR '1'='1"
    elif request.vuln_type == "SSRF":
        payload = "http://169.254.169.254/latest/meta-data/"
    else:
        raise HTTPException(status_code=400, detail="Unsupported vulnerability type")
    
    # 3. Determine status based on AI analysis
    status_result = "success" if "secure" in ai_analysis.lower() else "failed"
    
    # 4. Save scan to history
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (user_id, target_url, vuln_type, ai_analysis, execution_payload, status) VALUES (?, ?, ?, ?, ?, ?)",
        (current_user["id"], request.target_url, request.vuln_type, ai_analysis, payload, status_result)
    )
    conn.commit()
    conn.close()
    
    return {
        "target_url": request.target_url,
        "vuln_type": request.vuln_type,
        "ai_analysis": ai_analysis,
        "execution_payload": payload,
        "status": status_result
    }

@app.get("/api/v1/history", response_model=List[ScanHistory])
def get_history(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    scans = conn.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC",
        (current_user["id"],)
    ).fetchall()
    conn.close()
    return [dict(scan) for scan in scans]

# ---------- MOCK ENDPOINTS ----------
@app.get("/mock-target/admin/dashboard")
def mock_admin_dashboard():
    return {"message": "Welcome to the Secure Admin Panel", "access": "granted"}

@app.get("/mock-target/login/db")
def mock_login_db(username: str = "", password: str = ""):
    if "1'='1" in username or "1'='1" in password:
        return {"status": "authenticated", "bypass": True}
    return {"status": "unauthorized", "bypass": False}

@app.get("/mock-target/preview")
def mock_preview(url: str = ""):
    if "169.254.169.254" in url:
        return {"status": "success", "ssrf_detected": True, "metadata": "AWS-METADATA-v1"}
    return {"status": "success", "ssrf_detected": False}

@app.get("/")
async def root():
    return {"message": "NEMESIS AI Security Engine is running", "status": "online"}

# ---------- SERVER START ----------
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)