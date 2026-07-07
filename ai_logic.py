
import os
import openai
import requests


_cache = {}


KNOWLEDGE_DIR = "rag_knowledge"
GROQ_API_KEY = "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"
SERPER_API_KEY = "98de95d9f23cfe0ee068a1ff872f3d93074f2255"  # 👈 YOUR KEY

VULN_FILES = {
    "Broken Access Control": "broken_access_control.txt",
    "SQL Injection": "sql_injection.txt",
    "SSRF": "ssrf.txt"
}

SYSTEM_PROMPTS = {
    "Broken Access Control": "You are a security expert. Analyze access control flaws. Provide a concise threat narrative.",
    "SQL Injection": "You are a security expert. Analyze SQL injection flaws. Provide a concise threat narrative.",
    "SSRF": "You are a security expert. Analyze SSRF flaws. Provide a concise threat narrative."
}

def load_local_context(vuln_type: str) -> str:
    filename = VULN_FILES.get(vuln_type)
    if not filename:
        return ""
    filepath = os.path.join(KNOWLEDGE_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return ""

def fetch_web_context(query: str, max_results: int = 3) -> str:
    """Search the web using Serper.dev (Google Search API)."""
    if not SERPER_API_KEY or SERPER_API_KEY == "98de95d9f23cfe0ee068a1ff872f3d93074f2255":
        return ""
    
    url = "https://google.serper.dev/search"
    headers = {
        "X-API-KEY": SERPER_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "q": query,
        "num": max_results
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        
        snippets = []
        for result in data.get("organic", []):
            if "snippet" in result:
                snippets.append(result["snippet"])
        return "\n\n".join(snippets)
    except Exception as e:
        print(f"[Web Search Error]: {e}")
        return ""

def generate_threat_analysis(target_url: str, vuln_type: str) -> str:
    
    cache_key = (target_url, vuln_type)
    if cache_key in _cache:
        print("[AI Engine]: Returning cached response")
        return _cache[cache_key]
    

    if vuln_type not in SYSTEM_PROMPTS:
        return f"Unsupported vulnerability type: {vuln_type}"

    
    local_context = load_local_context(vuln_type)

    
    web_context = ""
    if SERPER_API_KEY and SERPER_API_KEY != "98de95d9f23cfe0ee068a1ff872f3d93074f2255":
        query = f"{vuln_type} {target_url} vulnerability"
        web_context = fetch_web_context(query)

    combined = local_context
    if web_context:
        combined += "\n\n--- Web search results ---\n" + web_context
    if not combined:
        combined = "No reference context available."

    system_prompt = SYSTEM_PROMPTS[vuln_type]
    user_prompt = (
        f"Target URL: {target_url}\n"
        f"Vulnerability: {vuln_type}\n\n"
        f"Reference context:\n{combined}\n\n"
        "Provide a brief threat analysis for this target, focusing on the most relevant attack vectors."
    )

    client = openai.OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=GROQ_API_KEY
    )

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0
        )
        result = response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[AI Engine Error]: {str(e)}")
        result = f"AI analysis unavailable: {str(e)}"

   
    _cache[cache_key] = result
    

    return result