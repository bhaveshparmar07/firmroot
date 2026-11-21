"""Firmroot Cloud Run service.

Endpoints:
  GET  /health
  GET  /firmware            - list firmware blobs in GCS bucket
  POST /scan {"name": "..."} - start async scan, returns {scan_id, status}
  GET  /scan/{id}           - scan status + full report when done
  GET  /scans               - list recent scans from GCS
"""

import json
import os
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

PROJECT = os.environ.get("GCP_PROJECT", "bubbly-realm-457419-d4")
BUCKET = os.environ.get("FIRMWARE_BUCKET", "firmroot-scans-bubbly-realm-457419-d4")
WORKDIR = Path("/tmp/firmroot")

_gcs = None


def bucket():
    global _gcs
    if _gcs is None:
        from google.cloud import storage
        _gcs = storage.Client(project=PROJECT).bucket(BUCKET)
    return _gcs


def run_pipeline(image_path: Path, outdir: Path):
    """Run the Phase-1 pipeline (same code, no rewrite)."""
    import sys
    sys.path.insert(0, "/app/src")
    from firmroot.scan import run_scan
    return run_scan(str(image_path), str(outdir), use_gemini=True)


def _scan_meta_path(scan_id: str) -> str:
    return f"scans/{scan_id}/meta.json"


def _scan_report_path(scan_id: str) -> str:
    return f"scans/{scan_id}/report.json"


def _write_json(blob_path: str, data: dict):
    blob = bucket().blob(blob_path)
    blob.upload_from_string(json.dumps(data, indent=2, default=str),
                            content_type="application/json")


def _read_json(blob_path: str):
    blob = bucket().blob(blob_path)
    if not blob.exists():
        return None
    return json.loads(blob.download_as_text())


def do_scan(scan_id: str, name: str):
    """Background worker: download -> extract/analyze/gemini -> gcs."""
    try:
        _write_json(_scan_meta_path(scan_id), {
            "scan_id": scan_id, "firmware": name, "status": "running",
            "created_at": time.time()})
        blob = bucket().blob(f"firmware/{name}")
        local = WORKDIR / "images" / name
        local.parent.mkdir(parents=True, exist_ok=True)
        blob.download_to_filename(str(local))

        outdir = WORKDIR / "scans" / scan_id
        report = run_pipeline(local, outdir)

        # store full report JSON in GCS
        _write_json(_scan_report_path(scan_id), report)

        # compact meta with findings for dashboard
        gem_findings = {f["finding_id"]: f
                        for f in (report.get("gemini") or {}).get("findings", [])}
        findings = []
        for f in report.get("findings", []):
            t = gem_findings.get(f["finding_id"], {})
            findings.append({
                "finding_id": f["finding_id"],
                "type": f["type"],
                "binary": f["binary"],
                "service": f["service"],
                "user": f["user"],
                "matched_network_symbols": f["matched_network_symbols"],
                "matched_file_write_symbols": f["matched_file_write_symbols"],
                "supplementary": f.get("supplementary", {}),
                "title": t.get("title"),
                "explanation": t.get("explanation"),
                "priority": t.get("priority"),
                "attack_scenario": t.get("attack_scenario"),
                "permanent_fix": t.get("permanent_fix"),
                "immediate_mitigation": t.get("immediate_mitigation"),
                "compromise_indicators": t.get("compromise_indicators"),
            })

        _write_json(_scan_meta_path(scan_id), {
            "scan_id": scan_id,
            "firmware": name,
            "sha256": report.get("sha256"),
            "status": "done",
            "created_at": time.time(),
            "finished_at": time.time(),
            "services_enumerated": report.get("services_enumerated"),
            "binaries_analyzed": report.get("binaries_analyzed"),
            "scan_summary": (report.get("gemini") or {}).get("scan_summary"),
            "report_gcs_path": f"gs://{BUCKET}/{_scan_report_path(scan_id)}",
            "findings": findings,
            "gemini_error": report.get("gemini_error"),
        })
    except Exception as e:
        try:
            _write_json(_scan_meta_path(scan_id), {
                "scan_id": scan_id, "firmware": name, "status": "error",
                "error": str(e)[:2000], "finished_at": time.time()})
        except Exception:
            pass
        app.logger.exception("scan %s failed", scan_id)


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "firmroot", "project": PROJECT})


@app.get("/firmware")
def list_firmware():
    blobs = bucket().list_blobs(prefix="firmware/")
    return jsonify([b.name.split("/", 1)[1] for b in blobs if not b.name.endswith("/")])


@app.post("/scan")
def start_scan():
    body = request.get_json(force=True, silent=True) or {}
    name = body.get("name") or body.get("firmware")
    if not name:
        return jsonify({"error": "name required"}), 400
    # validate it exists in the bucket
    if not bucket().blob(f"firmware/{name}").exists():
        return jsonify({"error": f"firmware/{name} not found in bucket"}), 404
    scan_id = uuid.uuid4().hex[:12]
    threading.Thread(target=do_scan, args=(scan_id, name), daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "running"}), 202


@app.get("/scan/<scan_id>")
def get_scan(scan_id):
    meta = _read_json(_scan_meta_path(scan_id))
    if meta is None:
        return jsonify({"error": "not found"}), 404
    if meta.get("status") == "done":
        report = _read_json(_scan_report_path(scan_id))
        if report:
            meta["report"] = report
    return jsonify(meta)


@app.get("/scans")
def list_scans():
    blobs = bucket().list_blobs(prefix="scans/")
    ids = sorted({b.name.split("/")[1] for b in blobs
                  if b.name.endswith("/meta.json")}, reverse=True)
    out = []
    for sid in ids[:50]:
        meta = _read_json(_scan_meta_path(sid))
        if meta:
            meta.pop("findings", None)
            meta.pop("report", None)
            out.append(meta)
    out.sort(key=lambda m: m.get("created_at", 0), reverse=True)
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
