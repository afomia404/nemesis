from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import requests
from ai_logic import generate_threat_analysis

app = FastAPI()

# Enable CORS
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

# ---------- MAIN SIMULATION ENDPOINT ----------
@app.post("/api/v1/simulate")
def run_simulation(request: SimulationRequest):
    """
    AI‑powered vulnerability analysis.
    - AI generates payloads dynamically
    - AI analyzes each response
    - AI synthesizes the final report
    """
    
    # Step 1: Validate input
    if not request.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Step 2: Run the AI‑powered analysis
    try:
        # This function now handles everything:
        # - Payload generation (AI)
        # - Response analysis (AI)
        # - Report synthesis (AI)
        ai_analysis = generate_threat_analysis(
            request.target_url,
            request.vuln_type
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")
    
    # Step 3: Determine status from the AI's analysis
    # The AI returns a full report — we check if it found anything.
    # You can adjust this logic based on how your AI formats its response.
    status_result = "failed"  # default
    if "success" in ai_analysis.lower():
        status_result = "success"
    elif "vulnerable" in ai_analysis.lower():
        status_result = "failed"
    else:
        # If the AI is uncertain, treat as failed
        status_result = "failed"
    
    # Step 4: Return the result
    return {
        "target_url": request.target_url,
        "vuln_type": request.vuln_type,
        "ai_analysis": ai_analysis,
        "execution_payload": "AI‑generated (see analysis)",  # No single payload, it's a list
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
            "AI‑analyzed responses",
            "AI‑synthesized reports"
        ]
    }

# ---------- SERVER START ----------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)