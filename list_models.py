import os
import urllib.request
import json

user_key = os.environ.get("GEMINI_API_KEY","")
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={user_key}"
req = urllib.request.Request(url)
with urllib.request.urlopen(req, timeout=10) as resp:
    data = json.loads(resp.read().decode())
    for m in data.get("models", []):
        if "generateContent" in m.get("supportedGenerationMethods", []):
            print(m["name"])
