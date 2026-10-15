"""Two explicit demos of credential values appearing in the shared backend log."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
from threading import RLock
from time import perf_counter
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from django.conf import settings

from . import audit
from .assets import key_fingerprint, private_bytes
from .issuance import remaining, STATIC_TTL_SECONDS
from .registry import Consumer

_lock = RLock()


class ExposureConsumer(Consumer):
    @property
    def api_path(self):
        return f"/api/demo/exposure/{self.credential_type}/run/"


EXPOSURE_CONSUMERS = {
    "secret": ExposureConsumer("log-exposure-secret", "secret", "log-exposure-demo-secret", "manual_log_exposure", "authenticate"),
    "key": ExposureConsumer("log-exposure-key", "key", "log-exposure-demo-signing-key", "manual_log_exposure", "sign_verify"),
}


def _asset(consumer):
    parent = Path(settings.DEMO_ASSET_DIR) / "log-exposure"
    directory = parent / consumer.credential_type
    with _lock:
        if not directory.exists():
            parent.mkdir(mode=0o700, exist_ok=True)
            temporary = Path(tempfile.mkdtemp(prefix=".issuing-", dir=parent))
            try:
                if consumer.credential_type == "secret":
                    value = secrets.token_urlsafe(32)
                    fingerprint, basis = hashlib.sha256(value.encode()).hexdigest(), "value_utf8"
                    source, kind = "Azure Vault", "vault"
                else:
                    key = ed25519.Ed25519PrivateKey.generate()
                    value = private_bytes(key).decode()
                    fingerprint, basis = key_fingerprint(key), "public_key_spki"
                    source, kind = "PostgreSQL DB", "database"
                issued = datetime.now(timezone.utc)
                ttl = STATIC_TTL_SECONDS[consumer.credential_type]
                metadata = {
                    "issuance_id": str(uuid4()), "credential_version": "v1",
                    "issuance_source": source, "issuance_source_type": kind, "source_simulated": True,
                    "actual_issuer": "local-demo-generator", "issuance_time_origin": "local_generation",
                    "issued_at": issued.isoformat(), "expires_at": (issued + timedelta(seconds=ttl)).isoformat(),
                    "ttl_seconds": ttl, "fingerprint": fingerprint, "fingerprint_basis": basis,
                }
                for name, content in (("credential.txt", value), ("issuance.json", json.dumps(metadata))):
                    descriptor = os.open(temporary / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "w") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                temporary.rename(directory)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        return directory, json.loads((directory / "issuance.json").read_text())


def _record_issuance(metadata):
    with _lock:
        path = settings.DEMO_LOG_PATH
        if path.exists():
            with path.open() as stream:
                for line in stream:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if event.get("event_type") == "credential.issued" and event.get("issuance_id") == metadata["issuance_id"]:
                        return
        audit.emit("credential.issued", **{**metadata, "operation": "issue", "outcome": "success"})


def execute_exposure(consumer, payload):
    metadata = {
        "consumer_id": consumer.id, "consumer_name": consumer.name, "api_path": consumer.api_path,
        "credential_type": consumer.credential_type, "credential_name": consumer.credential_name,
        "asset_role": "log_exposure_demo", "intentional_value_logging": True, "credential_value_logged": False,
        "credential_version": None, "fingerprint": None, "fingerprint_basis": None,
        "issuance_id": None, "issuance_source": "Azure Vault" if consumer.credential_type == "secret" else "PostgreSQL DB",
        "issuance_source_type": "vault" if consumer.credential_type == "secret" else "database", "source_simulated": True,
        "issued_at": None, "expires_at": None, "ttl_seconds": None, "remaining_ttl_seconds": None,
        "retrieved_at": None, "retrieval_duration_ms": None,
        "operation": consumer.operation, "destination": consumer.api_path,
    }
    started = perf_counter()
    stage = "retrieval"
    try:
        audit.emit("credential.retrieval.started", **metadata)
        directory, issued = _asset(consumer)
        metadata.update({**remaining(issued), "fingerprint": None})
        value = (directory / "credential.txt").read_text()
        if consumer.credential_type == "secret":
            fingerprint = hashlib.sha256(value.encode()).hexdigest()
        else:
            key = serialization.load_pem_private_key(value.encode(), password=None)
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise ValueError("Expected Ed25519 key")
            fingerprint = key_fingerprint(key)
        metadata["fingerprint"] = fingerprint
        if not secrets.compare_digest(fingerprint, issued["fingerprint"]):
            metadata.update(issuance_id=None, issued_at=None, expires_at=None, ttl_seconds=None,
                            remaining_ttl_seconds=None, issuance_record_status="fingerprint_mismatch")
            raise ValueError("Unregistered demo material")
        metadata["issuance_record_status"] = "matched"
        if datetime.fromisoformat(issued["expires_at"]) <= datetime.now(timezone.utc):
            raise ValueError("Demo credential expired")
        _record_issuance(metadata)
        metadata.update(retrieved_at=audit.timestamp(), retrieval_duration_ms=round((perf_counter() - started) * 1000, 3))
        audit.emit("credential.retrieved", outcome="success", **metadata)
        stage = "usage"
        usage_started = perf_counter()
        if consumer.credential_type == "key":
            message = json.dumps({"consumer_id": consumer.id, "run_id": audit.context.get()["run_id"]}, sort_keys=True).encode()
            key.public_key().verify(key.sign(message), message)
        # This is the sole producer that intentionally includes raw demo material.
        audit.emit("credential.value.logged", **{**metadata, "credential_value_logged": True}, credential_value=value,
                   credential_value_encoding="utf8" if consumer.credential_type == "secret" else "pem_pkcs8",
                   outcome="success", log_contains_credential_value=True,
                   duration_ms=round((perf_counter() - usage_started) * 1000, 3))
        metadata["credential_value_logged"] = True
        result = {**metadata, "status": "success", "error_code": None,
                  "duration_ms": round((perf_counter() - usage_started) * 1000, 3)}
        audit.emit("credential.used", outcome="success", **result)
        return result
    except Exception as error:
        code = "AUDIT_UNAVAILABLE" if isinstance(error, audit.AuditUnavailable) else (
            "CREDENTIAL_UNAVAILABLE" if stage == "retrieval" else "CREDENTIAL_OPERATION_FAILED")
        if metadata["retrieval_duration_ms"] is None:
            metadata["retrieval_duration_ms"] = round((perf_counter() - started) * 1000, 3)
        result = {**metadata, "status": "failure", "error_code": code, "duration_ms": round((perf_counter() - started) * 1000, 3)}
        try:
            audit.emit("credential.failed", stage=stage, outcome="failure", **result)
        except audit.AuditUnavailable:
            result["error_code"] = "AUDIT_UNAVAILABLE"
        return result
