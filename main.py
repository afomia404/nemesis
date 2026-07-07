from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os


from ai_logic import generate_threat_analysis

app = FastAPI()

# Enable CORS (allow frontend to call this API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SimulationRequest(BaseModel):
    target_url: str
    vuln_type: str

# ---------- Mock endpoints (for testing) ----------
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

# ---------- Main simulation endpoint ----------
@app.post("/api/v1/simulate")
def run_simulation(request: SimulationRequest):
    # 1. Run your AI logic (real Groq + Serper)
    ai_analysis = generate_threat_analysis(request.target_url, request.vuln_type)

    # 2. Generate a payload based on vuln type
    if request.vuln_type == "Broken Access Control":
        payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZW1wbG95ZWVfNzciLCJyb2xlIjoiYWRtaW4ifQ"
    elif request.vuln_type == "SQL Injection":
        payload = "admin' OR '1'='1"
    elif request.vuln_type == "SSRF":
        payload = "http://169.254.169.254/latest/meta-data/"
    else:
        raise HTTPException(status_code=400, detail="Unsupported vulnerability type")

    # 3. Determine status based on AI analysis
    # If the AI mentions "vulnerable" → status = "failed" (detected a vulnerability)
    # Otherwise → "success" (no vulnerability found)
    status_result = "success" if "vulnerable" not in ai_analysis.lower() else "failed"

    # 4. Return the result
    return {
        "target_url": request.target_url,
        "vuln_type": request.vuln_type,
        "ai_analysis": ai_analysis,
        "execution_payload": payload,
        "status": status_result
    }

# ---------- Root endpoint ----------
@app.get("/")
async def root():
    return {"message": "NEMESIS AI Security Engine is running", "status": "online"}

# ---------- Server start ----------
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.getenv("PORT", 8000))  # default to 8000 locally
    uvicorn.run(app, host="0.0.0.0", port=port)