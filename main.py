from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import requests
from ai_logic import generate_threat_analysis, get_last_exploit_success

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

# ---------- MOCK ENDPOINTS (for testing) ----------
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

# ---------- MAIN SIMULATION ENDPOINT ----------
@app.post("/api/v1/simulate")
def run_simulation(request: SimulationRequest):
    # Validate input
    if not request.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    try:
        # Call the AI‑powered red team analysis
        ai_analysis = generate_threat_analysis(request.target_url, request.vuln_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

    # -------- UPDATED STATUS LOGIC --------
    # Check if any exploit actually succeeded (based on real attack results)
    any_success = get_last_exploit_success()
    status_result = "success" if any_success else "failed"

    return {
        "target_url": request.target_url,
        "vuln_type": request.vuln_type,
        "ai_analysis": ai_analysis,
        "execution_payload": "AI‑generated (see analysis)",
        "status": status_result
    }

# ---------- ROOT ENDPOINT ----------
@app.get("/")
async def root():
    return {
        "message": "NEMESIS AI Security Engine is running",
        "status": "online",
        "version": "2.0.0",
        "features": [
            "AI‑generated payloads",
            "Real HTTP requests",
            "Exploit confirmation (SUCCESS/FAILED based on actual exploit)",
            "Boolean, time‑based, UNION, and error‑based detection"
        ]
    }

# ---------- SERVER START ----------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)