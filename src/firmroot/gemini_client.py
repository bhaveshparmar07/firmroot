"""Gemini API client for structured finding triage.

Sends the evidence JSON to Gemini with a strict response_schema and
returns per-finding assessments covering the full lifecycle:
title, explanation, priority, attack_scenario, permanent_fix,
immediate_mitigation, compromise_indicators.
"""

import json
import os
import urllib.request
import urllib.error

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")
API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "title": {"type": "string"},
        "explanation": {"type": "string"},
        "priority": {"type": "string", "enum": ["High", "Medium", "Low"]},
        "attack_scenario": {"type": "string"},
        "permanent_fix": {"type": "string"},
        "immediate_mitigation": {"type": "string"},
        "compromise_indicators": {"type": "string"},
    },
    "required": ["finding_id", "title", "explanation", "priority",
                 "attack_scenario", "permanent_fix", "immediate_mitigation",
                 "compromise_indicators"],
}

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "scan_summary": {"type": "string"},
        "findings": {"type": "array", "items": FINDING_SCHEMA},
    },
    "required": ["scan_summary", "findings"],
}

PROMPT_TEMPLATE = """You are a senior IoT/embedded firmware security analyst reviewing \
structural analysis output from a firmware image. The analysis extracted the \
root filesystem, enumerated services that start at boot, and classified the \
dynamic symbols each service binary imports.

For EVERY candidate finding below, produce a complete lifecycle assessment.
For each finding, provide these fields:
- finding_id: copy from the input
- title: short name for the finding
- explanation: plain-language risk explanation
- priority: High, Medium, or Low
- attack_scenario: one concrete sentence on how this would actually be exploited
- permanent_fix: the real engineering fix
- immediate_mitigation: what an operator can do right now without a firmware update
- compromise_indicators: what to check for if this may already have been exploited

Rules:
- Base every statement on the concrete evidence provided (binary path, matched \
symbols, service config). Do not invent file paths, ports, or CVEs that are \
not supported by the evidence — if a port is unknown, say "the service's \
listening port(s)" rather than guessing a number.
- priority must reflect real exploitability on an embedded device: a \
network-reachable unauthenticated root file-write is typically High.
- attack_scenario: ONE concrete sentence describing how this would actually \
be exploited end-to-end.
- permanent_fix: the real engineering fix (e.g. add authentication, validate \
paths, use O_NOFOLLOW, drop privileges, sandbox the service).
- immediate_mitigation: what an operator can do RIGHT NOW on a device already \
in the field without a firmware update — network segmentation, firewalling \
the port, disabling the service if non-essential, rotating exposed credentials.
- compromise_indicators: specific things to check if the device may already \
have been exploited — concrete file paths, timestamps, ownership, or log \
patterns an operator can inspect.
- If the evidence is too weak to support a real vulnerability (e.g. the \
"file write" symbols are only stderr logging), say so in explanation, set \
priority Low, and still fill all fields honestly.
- You may add findings of type "observation" only if strongly supported; \
prefer assessing the provided candidates.

Firmware: {firmware_name}
SHA256: {sha256}

Candidate findings (JSON):
{findings_json}

Return your response as a JSON object with a "scan_summary" string and a \
"findings" array containing objects with the fields listed above. \
Return ONLY the JSON object, no markdown or explanation."""


def _load_key():
    key = os.environ.get("GEMINI_API_KEY")
    if key:
        return key
    envfile = os.path.join(os.path.dirname(__file__), "..", "..",
                           "environment", ".env")
    envfile = os.path.abspath(envfile)
    if os.path.exists(envfile):
        with open(envfile) as f:
            for line in f:
                if line.startswith("GEMINI_API_KEY="):
                    return line.split("=", 1)[1].strip()
    return None


def call_gemini(evidence, model=None, timeout=180):
    """Send evidence to Gemini, return parsed response dict."""
    key = _load_key()
    if not key:
        raise RuntimeError("GEMINI_API_KEY not set (env or environment/.env)")
    model = model or DEFAULT_MODEL

    findings = evidence.get("findings", [])
    prompt = PROMPT_TEMPLATE.format(
        firmware_name=os.path.basename(evidence.get("image", "firmware")),
        sha256=evidence.get("sha256", "unknown"),
        findings_json=json.dumps(findings, indent=2)[:60000],
    )

    # Use the official Python library which handles the AQ.Ab8 key format
    try:
        from google import generativeai as genai
        genai.configure(api_key=key)
        gm = genai.GenerativeModel(model)
        response = gm.generate_content(prompt)
        text = response.text.strip()
        # Try to fix common JSON issues (trailing commas, etc.)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Remove trailing commas before } or ]
            import re
            fixed = re.sub(r",(\s*[}\]])", r"\1", text)
            return json.loads(fixed)
    except ImportError:
        # Fallback to urllib if library not installed
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
                "temperature": 0.2,
                "maxOutputTokens": 8192,
            },
        }
        url = f"{API_BASE}/{model}:generateContent?key={key}"
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:2000]
            raise RuntimeError(f"Gemini API HTTP {e.code}: {detail}") from e

        try:
            text = resp["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Unexpected Gemini response shape: {json.dumps(resp)[:1500]}") from e
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            import re
            fixed = re.sub(r",(\s*[}\]])", r"\1", text)
            return json.loads(fixed)
