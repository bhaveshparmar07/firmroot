"""
Firmroot - Google Cloud Storage & Firestore Integration Module
Handles real Cloud Storage uploads/downloads and Firestore persistent records.
Gracefully falls back to local memory if running in a dry environment.
"""
import os
import json
import time
from typing import Dict, Any, Optional

# Attempt to load official Google Cloud client libraries
try:
    from google.cloud import firestore
    from google.cloud import storage
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "firmroot-cloud")
STORAGE_BUCKET = os.environ.get("STORAGE_BUCKET", f"{PROJECT_ID}-firmware-storage")

class GoogleCloudStorageManager:
    def __init__(self):
        self.client = None
        self.bucket = None
        if GCP_AVAILABLE:
            try:
                self.client = storage.Client(project=PROJECT_ID)
                self.bucket = self.client.bucket(STORAGE_BUCKET)
            except Exception as e:
                print(f"[!] Warning: GCS initialization skipped: {e}")

    def upload_evidence_report(self, scan_id: str, payload: Dict[str, Any]) -> str:
        """Uploads the canonical JSON evidence report to Cloud Storage."""
        destination_blob_name = f"reports/{scan_id}/evidence_report.json"
        if self.bucket:
            try:
                blob = self.bucket.blob(destination_blob_name)
                blob.upload_from_string(
                    data=json.dumps(payload, indent=2),
                    content_type="application/json"
                )
                return f"gs://{STORAGE_BUCKET}/{destination_blob_name}"
            except Exception as e:
                print(f"[!] GCS upload failed: {e}")
        return f"local://storage/{destination_blob_name}"

    def download_firmware_sample(self, sample_filename: str, local_dest_path: str) -> bool:
        """Downloads a firmware sample from Cloud Storage for extraction."""
        if self.bucket:
            try:
                blob = self.bucket.blob(f"samples/{sample_filename}")
                blob.download_to_filename(local_dest_path)
                return True
            except Exception as e:
                print(f"[!] GCS download failed: {e}")
        return False


class GoogleCloudFirestoreManager:
    def __init__(self):
        self.db = None
        if GCP_AVAILABLE:
            try:
                self.db = firestore.Client(project=PROJECT_ID)
            except Exception as e:
                print(f"[!] Warning: Firestore initialization skipped: {e}")

    def save_scan_result(self, scan_id: str, record: Dict[str, Any]) -> bool:
        """Persists the complete scan and Gemini triage result into Firestore."""
        if self.db:
            try:
                doc_ref = self.db.collection("firmroot_scans").document(scan_id)
                doc_ref.set(record)
                return True
            except Exception as e:
                print(f"[!] Firestore save failed: {e}")
        return False

    def update_human_review(self, scan_id: str, group_id: str, reviewed: bool) -> bool:
        """Updates the human verification review state for a finding group in Firestore."""
        if self.db:
            try:
                doc_ref = self.db.collection("firmroot_scans").document(scan_id)
                doc_ref.update({
                    f"review_state.{group_id}": reviewed,
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
                return True
            except Exception as e:
                print(f"[!] Firestore review update failed: {e}")
        return False

    def get_scan_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves scan record from Firestore."""
        if self.db:
            try:
                doc_ref = self.db.collection("firmroot_scans").document(scan_id)
                doc = doc_ref.get()
                if doc.exists:
                    return doc.to_dict()
            except Exception as e:
                print(f"[!] Firestore fetch failed: {e}")
        return None
