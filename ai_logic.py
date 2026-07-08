import os
import json
import requests
from openai import OpenAI

# ---------- CONFIG ----------
GROQ_API_KEY = os.getenv("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")
SERPER_API_KEY = os.getenv("98de95d9f23cfe0ee068a1ff872f3d93074f2255")

# ---------- CACHE ----------
_cache = {}

# ---------- AI CLIENT ----------
client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=GROQ_API_KEY
)

# ---------- 1. AI GENERATES PAYLOADS ----------
def ai_generate_payloads(target_url: str, vuln_type: str, num_payloads: int = 5) -> list:
    """Use AI to generate context‑aware payloads for the target."""
    
    cache_key = f"payloads_{target_url}_{vuln_type}"
    if cache_key in _cache:
        return _cache[cache_key]
    
    prompt = f"""
You are a world‑class penetration tester. Generate {num_payloads} realistic, high‑impact payloads for testing {vuln_type} on this target: {target_url}.

Rules:
- Return ONLY a JSON array of strings.
- Each payload must be unique and context‑aware.
- Include obfuscation techniques (encoding, comments, case variation).
- Do NOT include any explanation, only the JSON array.

Example format: ["payload1", "payload2", "payload3"]
"""
    
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security expert. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7  # Slight creativity for variety
        )
        raw = response.choices[0].message.content.strip()
        # Extract JSON array from response
        start = raw.find('[')
        end = raw.rfind(']') + 1
        if start != -1 and end != 0:
            payloads = json.loads(raw[start:end])
        else:
            # Fallback if AI doesn't return JSON
            payloads = [raw]
        
        _cache[cache_key] = payloads
        return payloads
    except Exception as e:
        print(f"[AI Payload Generation Error]: {e}")
        # Fallback to basic payloads
        return get_fallback_payloads(vuln_type)

# ---------- 2. AI ANALYZES RESPONSE ----------
def ai_analyze_response(response_text: str, payload: str, vuln_type: str) -> dict:
    """Use AI to determine if the response indicates a successful exploit."""
    
    prompt = f"""
You are a security analyst. Analyze this HTTP response to determine if the payload successfully exploited a {vuln_type} vulnerability.

Payload sent: {payload}

Response:
{response_text[:2000]}

Answer with a JSON object:
{{
    "success": true/false,
    "reason": "Brief explanation of why it succeeded or failed",
    "confidence": "high/medium/low"
}}
"""
    
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security analyst. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0  # Factual
        )
        raw = response.choices[0].message.content.strip()
        # Extract JSON
        start = raw.find('{')
        end = raw.rfind('}') + 1
        if start != -1 and end != 0:
            result = json.loads(raw[start:end])
        else:
            result = {"success": False, "reason": "AI parsing failed", "confidence": "low"}
        
        return result
    except Exception as e:
        print(f"[AI Response Analysis Error]: {e}")
        return {"success": False, "reason": str(e), "confidence": "low"}

# ---------- 3. AI SYNTHESIZES FINAL REPORT ----------
def ai_synthesize_report(target_url: str, vuln_type: str, results: list) -> str:
    """Use AI to generate a comprehensive threat narrative from all test results."""
    
    prompt = f"""
You are a senior security consultant. Based on the following test results for {target_url} ({vuln_type}), generate a professional threat narrative.

Test Results:
{json.dumps(results, indent=2)}

Your report must include:
1. Executive summary (1‑2 sentences)
2. Attack vector explanation
3. Successful payloads (if any)
4. Impact assessment
5. Remediation steps

Write in a clear, professional tone. No markdown, just plain text.
"""
    
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a senior security consultant. Write professional security reports."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[AI Report Synthesis Error]: {e}")
        return f"Analysis failed: {str(e)}"

# ---------- 4. FALLBACK PAYLOADS (if AI fails) ----------
def get_fallback_payloads(vuln_type: str) -> list:
    """Hardcoded fallback payloads — only used if AI fails."""
    fallbacks = {
        "SQL Injection": [
            "admin' OR '1'='1' --",
            "admin' UNION SELECT 1,2,3 --",
            "admin' OR 1=1 --",
            "admin' AND SLEEP(5) --",
            "admin' OR '1'='1' /*"
        ],
        "Broken Access Control": [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ",
            "/admin/dashboard",
            "/admin/users",
            "/api/v1/users"
        ],
        "SSRF": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/admin",
            "http://localhost:80",
            "http://0.0.0.0:8000",
            "http://metadata.google.internal/"
        ]
    }
    return fallbacks.get(vuln_type, ["test"])

# ---------- 5. MAIN ORCHESTRATOR ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    """
    Main entry point — orchestrates the entire AI‑powered analysis.
    """
    
    # Step 1: AI generates payloads
    payloads = ai_generate_payloads(target_url, vuln_type)
    
    # Step 2: Test each payload (simulated — you'd replace with actual requests)
    results = []
    for payload in payloads:
        # Simulate a request (replace with actual HTTP call)
        response_text = f"Simulated response for payload: {payload}"
        
        # Step 3: AI analyzes the response
        analysis = ai_analyze_response(response_text, payload, vuln_type)
        
        results.append({
            "payload": payload,
            "analysis": analysis
        })
    
    # Step 4: AI synthesizes final report
    report = ai_synthesize_report(target_url, vuln_type, results)
    
    return report