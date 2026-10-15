"""Persistent issuance evidence for locally generated, source-labelled demo assets.

Source labels describe simulated integrations. They never assert an Azure,
PostgreSQL or Google network call actually issued these local credentials.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from threading import RLock
from uuid import NAMESPACE_URL, uuid5

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import audit
from .assets import certificate_fingerprint
from .registry import CONSUMERS, issuance_source

STATIC_TTL_SECONDS = {"secret": 86400, "key": 604800}
_lock = RLock()


def remaining(metadata, now=None):
    now = now or datetime.now(timezone.utc)
    return {**metadata, "remaining_ttl_seconds": max(0, int((datetime.fromisoformat(metadata["expires_at"]) - now).total_seconds()))}


def _fingerprint(reference, consumer):
    if consumer.credential_type == "secret":
        return hashlib.sha256(reference["expected_secret"].encode()).hexdigest(), "value_utf8"
    if consumer.credential_type == "certificate":
        return reference["fingerprint"], "certificate_der"
    key = serialization.load_pem_public_key(reference["public_key"].encode())
    public = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(public).hexdigest(), "public_key_spki"


def _write_private_json(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix=".issuance-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def ensure_issuances(root, *, origin="manifest_backfill"):
    """Register original issuance once; replay it if a log is newly created.

    Older demo directories retain their original creation time, material and
    fingerprints. Unknown replacement material is never silently re-issued.
    """
    root = Path(root)
    path = root / "issuance.json"
    log_path = root / "ecomm-demo.jsonl"
    with _lock:
        existing_metadata = path.exists()
        if existing_metadata:
            document = json.loads(path.read_text())
        else:
            manifest = json.loads((root / "manifest.json").read_text())
            references = json.loads((root / "provider.json").read_text())
            issued = datetime.fromisoformat(manifest["created_at"]).astimezone(timezone.utc).replace(microsecond=0)
            entries = {}
            for consumer in CONSUMERS:
                if consumer.credential_type == "oauth_token":
                    continue  # These are issued by the local token endpoint per request.
                fingerprint, basis = _fingerprint(references[consumer.id], consumer)
                expires_origin = "demo_lifetime_policy"
                if consumer.credential_type == "certificate":
                    try:
                        certificate = x509.load_pem_x509_certificate((root / f"{consumer.credential_name}.pem").read_bytes())
                    except (OSError, ValueError):
                        certificate = None
                    if certificate and certificate_fingerprint(certificate) == fingerprint:
                        expires = certificate.not_valid_after_utc
                        expires_origin = "x509_not_after"
                    else:
                        expires = issued + timedelta(days=30)
                else:
                    expires = issued + timedelta(seconds=STATIC_TTL_SECONDS[consumer.credential_type])
                entries[consumer.id] = {
                    "issuance_id": str(uuid5(NAMESPACE_URL, f"everyday-demo:{consumer.id}:{manifest['version']}:{fingerprint}")),
                    **issuance_source(consumer), "actual_issuer": "local-demo-generator",
                    "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
                    "expires_at_origin": expires_origin,
                    "ttl_seconds": max(0, int((expires - issued).total_seconds())),
                    "credential_version": manifest["version"], "fingerprint": fingerprint, "fingerprint_basis": basis,
                    "issuance_time_origin": origin,
                }
            document = {"schema_version": 1, "credentials": entries}
            _write_private_json(path, document)

        recorded = set()
        if log_path.exists():
            with log_path.open() as stream:
                for line in stream:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if event.get("event_type") == "credential.issued":
                        recorded.add(event.get("issuance_id"))
        for consumer in CONSUMERS:
            entry = document["credentials"].get(consumer.id)
            if entry and entry["issuance_id"] not in recorded:
                audit.emit("credential.issued", path=log_path, **remaining(entry),
                           consumer_id=consumer.id, consumer_name=consumer.name, api_path=consumer.api_path,
                           credential_type=consumer.credential_type, credential_name=consumer.credential_name,
                           asset_role="business", operation="issue", outcome="success",
                           historical_record=existing_metadata or origin != "local_generation",
                           issuance_record_reason="log_replay" if existing_metadata else origin,
                           caller="local-demo-initializer")
        return document["credentials"]


def static_issuance(root, consumer, fingerprint):
    entries = json.loads((Path(root) / "issuance.json").read_text())["credentials"]
    entry = entries[consumer.id]
    if entry["fingerprint"] != fingerprint:
        # A modified file is not evidence that a new version was legitimately issued.
        return {**issuance_source(consumer), "actual_issuer": "local-demo-generator",
                "issuance_id": None, "issued_at": None, "expires_at": None,
                "ttl_seconds": None, "remaining_ttl_seconds": None,
                "issuance_record_status": "fingerprint_mismatch"}
    return {**remaining(entry), "issuance_record_status": "matched"}


def token_issuance(consumer, claims, fingerprint, *, actual_issuer):
    issued = datetime.fromtimestamp(claims["iat"], timezone.utc)
    expires = datetime.fromtimestamp(claims["exp"], timezone.utc)
    return remaining({
        "issuance_id": claims["jti"], **issuance_source(consumer), "actual_issuer": actual_issuer,
        "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
        "ttl_seconds": int((expires - issued).total_seconds()),
        "credential_version": "v1", "fingerprint": fingerprint, "fingerprint_basis": "value_utf8",
        "issuance_time_origin": "local_token_endpoint", "issuance_record_status": "matched",
    })
