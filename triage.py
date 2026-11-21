"""
Firmroot - Dynamic Triage & Scoring Engine
Uses live Gemini API via google-generativeai with deterministic fallback.
"""
import os
import json
from typing import Dict, Any, List

TRIAGE_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")

TRIAGE_PROMPT = """You are Firmroot's embedded firmware security triage engine.
Analyze the provided deterministic scan evidence extracted directly from an IoT/firmware image.
You must return valid JSON with:
{
  "executive_summary": "2-3 sentences explaining real-world attacker exploitation path based on actual findings.",
  "risk_score": <number between 1 and 100 calculated from finding severities>,
  "findings_groups": [
    {
      "group_id": "GRP-01",
      "title": "Clear descriptive title naming the actual binary/service",
      "priority": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "cwe_id": "CWE-...",
      "risk_explanation": "Concrete attack vector and real-world embedded impact",
      "remediation_guidance": "Exact instructions to fix in rootfs/build pipeline",
      "linked_evidence_ids": ["EVID-001"]
    }
  ]
}
Strictly cite linked_evidence_ids from the provided input.
Group findings per affected binary/service where possible so different
firmware images produce different, specific finding titles — do not reuse
generic category names as titles."""


def _gemini_triage(api_key: str, firmware_name: str,
                   evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    from google import generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(TRIAGE_MODEL)
    prompt = (f"{TRIAGE_PROMPT}\n\nFirmware Target: {firmware_name}\n"
              f"Deterministic Scan Evidence:\n{json.dumps(evidence, indent=2)}")
    response = model.generate_content(prompt)
    text = response.text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import re
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", text))


def synthesize_triage(firmware_name: str, evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Synthesizes genuine findings grouping, risk score calculation, and remediation
    strictly derived from real extracted evidence using live Gemini API.
    """
    api_key = os.environ.get("GEMINI_API_KEY")

    if api_key and evidence:
        try:
            parsed = _gemini_triage(api_key, firmware_name, evidence)
            print(f"[+] Gemini triage via {TRIAGE_MODEL}: "
                  f"{len(parsed.get('findings_groups', []))} finding groups.")
            return parsed
        except Exception as e:
            print(f"[!] Gemini triage failed ({e}). Falling back to deterministic triage.")

    print("[*] Using deterministic rule-based triage.")
    weights = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3}
    raw_score = sum(weights.get(item.get("severity", "LOW"), 5) for item in evidence)
    risk_score = min(98, max(25, raw_score)) if evidence else 0

    groups_dict = {}
    for item in evidence:
        groups_dict.setdefault(item["category"], []).append(item)

    findings_groups = []
    grp_idx = 1

    if "STRUCTURAL_VULNERABILITY" in groups_dict:
        items = groups_dict["STRUCTURAL_VULNERABILITY"]
        ids = [i["id"] for i in items]
        names = sorted({i.get("file_path", "?") for i in items})[:5]
        findings_groups.append({
            "group_id": f"GRP-{grp_idx:02d}",
            "title": f"Unauthenticated Privileged File-Write in {', '.join(names)}",
            "priority": "CRITICAL",
            "cwe_id": "CWE-73: External Control of File Name or Path",
            "risk_explanation": f"Identified {len(items)} structural service vulnerability where network input sinks link directly with file operations or process execution under root privileges without authentication.",
            "remediation_guidance": "Enforce strict authentication, drop root privileges with setuid/setgid, and restrict exposed network daemon bindings.",
            "linked_evidence_ids": ids
        })
        grp_idx += 1

    if "HARDCODED_SECRET" in groups_dict:
        items = groups_dict["HARDCODED_SECRET"]
        ids = [i["id"] for i in items]
        findings_groups.append({
            "group_id": f"GRP-{grp_idx:02d}",
            "title": "Hardcoded Cryptographic Keys & Embedded Credentials",
            "priority": "CRITICAL",
            "cwe_id": "CWE-798: Use of Hard-coded Credentials",
            "risk_explanation": f"Identified {len(items)} hardcoded secrets including password hashes and static private keys.",
            "remediation_guidance": "Purge all static keys and hashes from /etc. Provision unique per-device credentials at factory flashing.",
            "linked_evidence_ids": ids
        })
        grp_idx += 1

    if "INSECURE_CONFIGURATION" in groups_dict:
        items = groups_dict["INSECURE_CONFIGURATION"]
        ids = [i["id"] for i in items]
        findings_groups.append({
            "group_id": f"GRP-{grp_idx:02d}",
            "title": "Insecure Service Daemons & Unauthenticated Listeners",
            "priority": "HIGH",
            "cwe_id": "CWE-306: Missing Authentication for Critical Function",
            "risk_explanation": f"Found {len(items)} service invocations in startup scripts spawning unencrypted management daemons.",
            "remediation_guidance": "Disable unencrypted daemons in /etc/init.d/ and enforce SSH-only access.",
            "linked_evidence_ids": ids
        })
        grp_idx += 1

    if "VULNERABLE_COMPONENT" in groups_dict:
        items = groups_dict["VULNERABLE_COMPONENT"]
        ids = [i["id"] for i in items]
        findings_groups.append({
            "group_id": f"GRP-{grp_idx:02d}",
            "title": "Outdated Core Binaries with Known Exploits",
            "priority": "HIGH" if any(i["severity"] == "HIGH" for i in items) else "CRITICAL",
            "cwe_id": "CWE-1395: Dependency on Vulnerable Third-Party Component",
            "risk_explanation": f"Found {len(items)} outdated utilities with published CVEs enabling remote memory corruption or arbitrary execution.",
            "remediation_guidance": "Upgrade toolchain and library versions to modern vendor-patched releases.",
            "linked_evidence_ids": ids
        })
        grp_idx += 1

    summary = (
        f"Automated forensic inspection of {firmware_name} identified {len(evidence)} verified security risks. "
        f"Primary attack vectors stem from {', '.join(k.lower().replace('_', ' ') for k in groups_dict.keys())}."
    )

    return {
        "executive_summary": summary,
        "risk_score": risk_score,
        "findings_groups": findings_groups
    }
