"""
Firmroot - Deterministic Evidence Aggregator & Pipeline Runner
"""
import os
import json
import time
from typing import Dict, Any

from scanners.secrets import scan_secrets
from scanners.components import scan_components
from scanners.configs import scan_configs

def run_pipeline(root_dir: str, firmware_name: str) -> Dict[str, Any]:
    start_time = time.time()
    
    # 1. Run all deterministic checks
    secrets_found = scan_secrets(root_dir)
    components_found = scan_components(root_dir)
    configs_found = scan_configs(root_dir)
    
    duration = round(time.time() - start_time, 2)
    
    # 2. Structure evidence with unique deterministic IDs
    evidence_items = []
    item_counter = 1
    
    for item in secrets_found:
        evidence_items.append({
            "id": f"EVID-{item_counter:03d}",
            "category": "HARDCODED_SECRET",
            **item
        })
        item_counter += 1
        
    for item in components_found:
        evidence_items.append({
            "id": f"EVID-{item_counter:03d}",
            "category": "VULNERABLE_COMPONENT",
            **item
        })
        item_counter += 1
        
    for item in configs_found:
        evidence_items.append({
            "id": f"EVID-{item_counter:03d}",
            "category": "INSECURE_CONFIGURATION",
            **item
        })
        item_counter += 1
        
    structured_payload = {
        "metadata": {
            "firmware_name": firmware_name,
            "scan_timestamp": int(time.time()),
            "scan_duration_seconds": duration,
            "total_raw_evidence_count": len(evidence_items)
        },
        "evidence": evidence_items
    }
    
    return structured_payload
