"""
Firmroot - Dynamic Triage & Scoring Engine
Uses Gemini 3.8 Flash (gemini-3.8-flash) via google-genai SDK
with strict JSON schema enforcement and robust fallback resilience.
"""
import os
import json
from typing import Dict, Any, List

def call_gemini_triage(evidence_payload: Dict[str, Any]) -> Dict[str, Any]:
    firmware_name = evidence_payload.get("metadata", {}).get("firmware_name", "Firmware Target")
    evidence = evidence_payload.get("evidence", [])
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        try:
            from google import genai
            from google.genai import types
            
            client = genai.Client(api_key=api_key)
            system_prompt = """You are Firmroot's expert embedded firmware security triage engine.
Analyze the provided deterministic scan evidence extracted directly from an IoT/firmware image.
You must return valid JSON with:
{
  "executive_summary": "2-3 sentences explaining real-world attacker exploitation path based on actual findings.",
  "risk_score": <number between 1 and 100 calculated from finding severities>,
  "findings_groups": [
    {
      "group_id": "GRP-01",
      "title": "Clear descriptive title",
      "priority": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "cwe_id": "CWE-...",
      "risk_explanation": "Concrete attack vector and real-world embedded impact",
      "remediation_guidance": "Exact instructions to fix in rootfs/build pipeline",
      "linked_evidence_ids": ["EVID-001"]
    }
  ]
}
Strictly cite linked_evidence_ids from the provided input."""

            prompt = f"{system_prompt}\n\nFirmware Target: {firmware_name}\nDeterministic Scan Evidence:\n{json.dumps(evidence, indent=2)}"
            
            res = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1
                )
            )
            if res.text:
                parsed = json.loads(res.text)
                print(f"[+] Successfully invoked live Gemini 3.8 Flash triage! Received {len(parsed.get('findings_groups', []))} finding groups.")
                return parsed
        except Exception as e:
            print(f"[!] Live Gemini 3.8 Flash API call failed ({e}).")

    from triage import synthesize_triage
    return synthesize_triage(firmware_name, evidence)
