import base64
from datetime import datetime, timezone
import hashlib
import json
from time import perf_counter
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from django.conf import settings
import jwt
import requests

from . import audit
from .assets import certificate_fingerprint, key_fingerprint
from .issuance import static_issuance, token_issuance
from .provider import canonical
from .registry import CONSUMERS, issuance_source


class DemoFailure(Exception):
    def __init__(self, result):
        self.result = result
        super().__init__("A demo credential dependency failed.")


def execute(consumer, payload):
    root = settings.DEMO_ASSET_DIR
    metadata = {"consumer_id": consumer.id, "consumer_name": consumer.name, "api_path": consumer.api_path,
                "credential_type": consumer.credential_type, "credential_name": consumer.credential_name, "asset_role": "business",
                "credential_version": None, "fingerprint": None, "fingerprint_basis": None,
                "retrieved_at": None, "retrieval_duration_ms": None, "operation": consumer.operation,
                "destination": settings.DEMO_PROVIDER_URL + "/targets/" + consumer.id,
                **issuance_source(consumer), "issuance_id": None, "issued_at": None, "expires_at": None,
                "ttl_seconds": None, "remaining_ttl_seconds": None}
    stage = "retrieval"
    started = perf_counter()
    try:
        audit.emit("credential.retrieval.started", **metadata)
        metadata["credential_version"] = json.loads((root / "manifest.json").read_text())["version"]
        options = {}
        body = {"payload": payload}
        if consumer.credential_type == "secret":
            value = (root / f"{consumer.credential_name}.txt").read_text()
            if not value:
                raise ValueError("Empty credential")
            options["headers"] = {"X-API-Key": value}
            fingerprint = hashlib.sha256(value.encode()).hexdigest()
            basis = "value_utf8"
        elif consumer.credential_type == "certificate":
            certificate_path = root / f"{consumer.credential_name}.pem"
            key_path = root / f"{consumer.credential_name}.key.pem"
            certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise ValueError("Certificate key mismatch")
            if not certificate.not_valid_before_utc <= datetime.now(timezone.utc) < certificate.not_valid_after_utc:
                raise ValueError("Certificate outside validity period")
            options["cert"] = (str(certificate_path), str(key_path))
            fingerprint = certificate_fingerprint(certificate)
            basis = "certificate_der"
        elif consumer.credential_type == "key":
            key = serialization.load_pem_private_key((root / f"{consumer.credential_name}.key.pem").read_bytes(), password=None)
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise ValueError("Expected Ed25519 key")
            fingerprint = key_fingerprint(key)
            basis = "public_key_spki"
        else:
            client = json.loads((root / f"{consumer.id}.client.json").read_text())
            response = requests.post(settings.DEMO_PROVIDER_URL + "/demo-provider/token",
                                     auth=(client["client_id"], client["client_secret"]),
                                     data={"grant_type": "client_credentials", "scope": client["scope"]},
                                     verify=str(root / "ca.pem"), timeout=5, headers=trace_headers())
            response.raise_for_status()
            value = response.json()["access_token"]
            claims = jwt.decode(value, (root / "issuer.public.pem").read_bytes(), algorithms=["RS256"],
                                issuer=settings.DEMO_PROVIDER_URL, audience=client["audience"],
                                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"]})
            if claims["sub"] != consumer.id or claims.get("scope") != client["scope"]:
                raise ValueError("Token identity mismatch")
            options["headers"] = {"Authorization": "Bearer " + value}
            fingerprint = hashlib.sha256(value.encode()).hexdigest()
            basis = "value_utf8"
            metadata.update(token_issuance(consumer, claims, fingerprint, actual_issuer=settings.DEMO_PROVIDER_URL))
        if consumer.credential_type != "oauth_token":
            metadata.update(static_issuance(root, consumer, fingerprint))
            if metadata["expires_at"] and datetime.fromisoformat(metadata["expires_at"]) <= datetime.now(timezone.utc):
                raise ValueError("Demo credential lifetime expired")
        metadata.update(fingerprint=fingerprint, fingerprint_basis=basis, retrieved_at=audit.timestamp(),
                        retrieval_duration_ms=round((perf_counter() - started) * 1000, 3))
        audit.emit("credential.retrieved", outcome="success", **metadata)
        stage = "usage"
        usage_started = perf_counter()
        if consumer.credential_type == "key":
            body["signature"] = base64.b64encode(key.sign(canonical(payload))).decode()
        options.setdefault("headers", {}).update(trace_headers())
        response = requests.post(metadata["destination"], json=body, timeout=5,
                                 verify=str(root / "ca.pem"), **options)
        response.raise_for_status()
        if response.json().get("verified") is not True:
            raise ValueError("Target did not verify credential")
        result = {**metadata, "status": "success", "error_code": None,
                  "duration_ms": round((perf_counter() - usage_started) * 1000, 3)}
        audit.emit("credential.used", outcome="success", **result)
        return result
    except Exception as error:
        # Exception messages and request/response objects can contain credentials.
        # Only allowlisted metadata and fixed codes cross the audit/API boundary.
        code = "AUDIT_UNAVAILABLE" if isinstance(error, audit.AuditUnavailable) else (
            "CREDENTIAL_UNAVAILABLE" if stage == "retrieval" else "CREDENTIAL_OPERATION_FAILED")
        if metadata["retrieval_duration_ms"] is None:
            metadata["retrieval_duration_ms"] = round((perf_counter() - started) * 1000, 3)
        result = {**metadata, "status": "failure", "error_code": code,
                  "duration_ms": round((perf_counter() - started) * 1000, 3)}
        try:
            audit.emit("credential.failed", stage=stage, outcome="failure", **result)
        except audit.AuditUnavailable:
            result["error_code"] = "AUDIT_UNAVAILABLE"
        return result


def trace_headers():
    return {"X-Demo-" + key.replace("_", "-"): value for key, value in audit.context.get().items() if key in {"request_id", "run_id"}}


def run(consumers, *, trigger, payload=None, caller=None, executor=None):
    values = {**audit.context.get(), "run_id": str(uuid4()), "trigger": trigger}
    values.setdefault("request_id", str(uuid4()))
    if caller is not None:
        values["caller"] = caller
    values.setdefault("caller", "anonymous")
    marker = audit.context.set(values)
    try:
        execute_consumer = executor or execute
        results = [execute_consumer(consumer, payload if payload is not None else {"demo": True, "consumer_id": consumer.id}) for consumer in consumers]
        response = {"request_id": values["request_id"], "run_id": values["run_id"], "results": results,
                    "summary": {"succeeded": sum(item["status"] == "success" for item in results),
                                "failed": sum(item["status"] == "failure" for item in results)}}
        try:
            audit.emit("run.completed", summary=response["summary"])
        except audit.AuditUnavailable:
            for item in results:
                item.update(status="failure", error_code="AUDIT_UNAVAILABLE")
            response["summary"] = {"succeeded": 0, "failed": len(results)}
        return response
    finally:
        audit.context.reset(marker)


def shopping(trigger, payload):
    if not getattr(settings, "DEMO_ENABLED", False):
        return
    response = run([consumer for consumer in CONSUMERS if consumer.trigger == trigger], trigger=trigger, payload=payload)
    if response["summary"]["failed"]:
        raise DemoFailure(response)
