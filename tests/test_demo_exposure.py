"""Intentional raw-value logging is restricted to two dedicated demo credentials."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest
from rest_framework.test import APIClient

from demo import audit
from demo.assets import key_fingerprint
from demo.exposure import EXPOSURE_CONSUMERS, execute_exposure
from demo.runtime import run
from .test_demo import buyer, local_demo, records, template  # noqa: F401


@pytest.mark.parametrize("kind", ["secret", "key"])
def test_exposure_endpoints_require_login_csrf_post_and_demo_mode(local_demo, buyer, settings, kind):
    path = f"/api/demo/exposure/{kind}/run/"
    anonymous = APIClient(enforce_csrf_checks=True)
    assert anonymous.post(path, {}, format="json").status_code == 403
    client, csrf = buyer
    assert client.post(path, {}, format="json").status_code == 403
    assert client.get(path).status_code == 405
    assert not (local_demo.root / "log-exposure").exists()
    settings.DEMO_ENABLED = False
    assert client.post(path, {}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code == 404
    assert not (local_demo.root / "log-exposure").exists()


@pytest.mark.parametrize("kind", ["secret", "key"])
def test_only_dedicated_values_appear_in_explicit_log_events_and_never_api_results(local_demo, buyer, kind):
    client, csrf = buyer
    consumer = EXPOSURE_CONSUMERS[kind]
    responses = [client.post(consumer.api_path, {"credential_value": "untrusted-body-canary"}, format="json", HTTP_X_CSRFTOKEN=csrf) for _ in range(2)]
    assert all(response.status_code == 200 for response in responses)
    directory = local_demo.root / "log-exposure" / kind
    value = (directory / "credential.txt").read_text()
    events = records(local_demo)
    exposed = [event for event in events if event["event_type"] == "credential.value.logged"]
    assert len(exposed) == 2 and all(event["credential_value"] == value for event in exposed)
    if kind == "secret":
        fingerprint = hashlib.sha256(value.encode()).hexdigest()
    else:
        key = serialization.load_pem_private_key(value.encode(), password=None)
        assert isinstance(key, ed25519.Ed25519PrivateKey)
        fingerprint = key_fingerprint(key)
    results = [response.json()["results"][0] for response in responses]
    assert {result["fingerprint"] for result in results} == {fingerprint}
    assert len({result["issuance_id"] for result in results}) == 1
    for result in results:
        assert result["status"] == "success" and result["credential_value_logged"] is True
        assert result["retrieved_at"] and result["retrieval_duration_ms"] >= 0
        assert result["ttl_seconds"] == (86400 if kind == "secret" else 604800)
    for event, response in zip(exposed, responses):
        assert event["environment"] == "testing" and event["caller"] != "anonymous"
        assert event["intentional_value_logging"] and event["credential_value_logged"]
        assert event["asset_role"] == "log_exposure_demo" and event["source_simulated"]
        assert event["request_id"] == response.json()["request_id"]
        assert event["run_id"] == response.json()["run_id"]
        assert event["fingerprint"] == fingerprint
    issued = [event for event in events if event["event_type"] == "credential.issued" and event.get("asset_role") == "log_exposure_demo"]
    assert len(issued) == 1 and issued[0]["issuance_id"] == results[0]["issuance_id"]
    assert all("credential_value" not in event for event in events if event["event_type"] != "credential.value.logged")
    assert all(json.dumps(value) not in json.dumps(response.json()) for response in responses)
    assert "untrusted-body-canary" not in json.dumps(events)
    assert directory.parent.stat().st_mode & 0o777 == directory.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())
    for reference in local_demo.references.values():
        if reference["type"] == "secret":
            assert reference["expected_secret"] not in json.dumps(events)


def test_run_all_still_runs_only_twelve_business_consumers_without_value_logging(local_demo, buyer):
    client, csrf = buyer
    response = client.post("/api/demo/run/", {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.json()["summary"] == {"succeeded": 12, "failed": 0}
    assert len(client.get("/api/demo/services/").json()["services"]) == 12
    assert not (local_demo.root / "log-exposure").exists()
    assert not any(event["event_type"] == "credential.value.logged" for event in records(local_demo))


@pytest.mark.parametrize("kind", ["secret", "key"])
@pytest.mark.parametrize("failure", ["missing", "mismatched", "expired"])
def test_invalid_exposure_assets_fail_without_reissue_or_logging_the_value(local_demo, buyer, kind, failure):
    client, csrf = buyer
    path = EXPOSURE_CONSUMERS[kind].api_path
    assert client.post(path, {}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code == 200
    directory = local_demo.root / "log-exposure" / kind
    asset = directory / "credential.txt"
    original = asset.read_bytes()
    if failure == "missing":
        asset.unlink()
    elif failure == "mismatched":
        asset.write_text("unregistered-material-canary")
    else:
        issuance_path = directory / "issuance.json"
        document = json.loads(issuance_path.read_text())
        document["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        issuance_path.write_text(json.dumps(document))
    response = client.post(path, {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 503
    result = response.json()["results"][0]
    assert result["error_code"] == "CREDENTIAL_UNAVAILABLE" and not result["credential_value_logged"]
    events = records(local_demo)
    assert len([event for event in events if event["event_type"] == "credential.value.logged"]) == 1
    assert len([event for event in events if event["event_type"] == "credential.issued" and event.get("asset_role") == "log_exposure_demo"]) == 1
    assert "unregistered-material-canary" not in json.dumps(events) + response.content.decode()
    if failure == "missing":
        assert not asset.exists()
        assert result["fingerprint"] is None
    elif failure == "expired":
        assert asset.read_bytes() == original


def test_unavailable_audit_prevents_exposure_asset_generation(local_demo, settings):
    settings.DEMO_LOG_PATH = local_demo.root / "missing" / "audit.jsonl"
    result = run([EXPOSURE_CONSUMERS["secret"]], trigger="manual_log_exposure", executor=execute_exposure)
    assert result["results"][0]["error_code"] == "AUDIT_UNAVAILABLE"
    assert not (local_demo.root / "log-exposure").exists()


@pytest.mark.parametrize("kind", ["secret", "key"])
def test_value_audit_failure_cannot_report_success(local_demo, buyer, monkeypatch, kind):
    client, csrf = buyer
    emit = audit.emit
    def unavailable(event, **fields):
        if event == "credential.value.logged":
            raise audit.AuditUnavailable()
        return emit(event, **fields)
    monkeypatch.setattr(audit, "emit", unavailable)
    response = client.post(EXPOSURE_CONSUMERS[kind].api_path, {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 503
    assert response.json()["results"][0]["error_code"] == "AUDIT_UNAVAILABLE"
    assert response.json()["results"][0]["credential_value_logged"] is False
    assert not any("credential_value" in event for event in records(local_demo))


def test_concurrent_exposure_calls_reuse_credentials_and_write_complete_correlated_jsonl(local_demo):
    consumers = [EXPOSURE_CONSUMERS[kind] for kind in ("secret", "key") * 4]
    def invoke(consumer):
        return run([consumer], trigger="manual_log_exposure", executor=execute_exposure)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(invoke, consumers))
    assert all(result["summary"] == {"succeeded": 1, "failed": 0} for result in results)
    events = records(local_demo)
    exposed = [event for event in events if event["event_type"] == "credential.value.logged"]
    assert len(exposed) == 8
    assert {event["run_id"] for event in exposed} == {result["run_id"] for result in results}
    assert len({event["issuance_id"] for event in exposed}) == 2
    assert len([event for event in events if event["event_type"] == "credential.issued" and event.get("asset_role") == "log_exposure_demo"]) == 2
    assert len({event["event_id"] for event in events}) == len(events)
