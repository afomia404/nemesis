# test_ai.py
from ai_logic import generate_threat_analysis

result = generate_threat_analysis("http://test.com/login", "SQL Injection")
print("AI Analysis:", result)
print("Type:", type(result))