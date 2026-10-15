from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.contrib.auth import get_user_model
import jwt
import pytest
import requests
from rest_framework.test import APIClient

from demo import audit
from demo.assets import initialize
from demo.issuance import ensure_issuances
from demo.provider import LocalProvider
from demo.registry import BY_ID, CONSUMERS
from demo.runtime import run
from shop.models import Order, Product


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    return initialize(tmp_path_factory.mktemp("demo-template") / "assets")


@pytest.fixture
def local_demo(template, tmp_path, settings):
    root = tmp_path / "assets"
    shutil.copytree(template, root)
    settings.DEMO_ENABLED = True
    settings.SESSION_COOKIE_NAME = "ecomm_demo_sessionid"
    settings.CSRF_COOKIE_NAME = "ecomm_demo_csrftoken"
    settings.DEMO_ASSET_DIR = root
    settings.DEMO_LOG_PATH = root / "ecomm-demo.jsonl"
    settings.ROOT_URLCONF = "tests.demo_urls"
    settings.MIDDLEWARE = [*settings.MIDDLEWARE, "demo.middleware.DemoAuditMiddleware"]
    with LocalProvider(root, port=0) as provider:
        settings.DEMO_PROVIDER_URL = provider.url
        yield provider


def invoke(*ids):
    return run([BY_ID[identity] for identity in ids], trigger="test")


def records(provider):
    return [json.loads(line) for line in (provider.root / "ecomm-demo.jsonl").read_text().splitlines()]


@pytest.mark.parametrize("value,expected", [
    ("Production", "production"), ("testing", "testing"),
    ("development", "development"), (" Staging ", "staging"),
])
def test_shared_writer_labels_every_event_with_the_configured_environment(tmp_path, monkeypatch, settings, value, expected):
    monkeypatch.setenv("ECOMM_DEMO_ENVIRONMENT", value)
    settings.DEMO_LOG_PATH = tmp_path / "audit.jsonl"
    marker = audit.context.set({"environment": "untrusted-context"})
    try:
        record = audit.emit("credential.issued", environment="untrusted-field")
        audit.SafeLogHandler().emit(logging.LogRecord("environment-test", logging.ERROR, __file__, 0, "safe", (), None))
    finally:
        audit.context.reset(marker)
    events = [json.loads(line) for line in settings.DEMO_LOG_PATH.read_text().splitlines()]
    assert record["environment"] == expected
    assert len(events) == 2 and all(event["environment"] == expected for event in events)


def test_environment_defaults_to_development_and_rejects_invalid_labels_before_writes(tmp_path, monkeypatch):
    monkeypatch.delenv("ECOMM_DEMO_ENVIRONMENT")
    assert audit.emit("default.environment", path=tmp_path / "default.jsonl")["environment"] == "development"
    monkeypatch.setenv("ECOMM_DEMO_ENVIRONMENT", "invalid-environment-canary")
    with pytest.raises(ValueError, match="ECOMM_DEMO_ENVIRONMENT must be"):
        initialize(tmp_path / "invalid-assets")
    with pytest.raises(ValueError, match="ECOMM_DEMO_ENVIRONMENT must be"):
        audit.emit("invalid.environment", path=tmp_path / "invalid.jsonl")
    assert not (tmp_path / "invalid-assets").exists()
    assert not (tmp_path / "invalid.jsonl").exists()


def test_initializer_is_idempotent_and_assets_are_private(template):
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in template.iterdir()}
    initialize(template)
    assert before == {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in template.iterdir()}
    assert template.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in template.iterdir())


def test_incomplete_directory_is_never_overwritten(tmp_path):
    (tmp_path / "preserve.txt").write_text("keep")
    with pytest.raises(ValueError, match="refusing"):
        initialize(tmp_path)
    assert (tmp_path / "preserve.txt").read_text() == "keep"


def test_twelve_consumers_retrieve_and_really_use_distinct_credentials(local_demo):
    first = run(CONSUMERS, trigger="test")
    second = run(CONSUMERS, trigger="test")
    assert first["summary"] == second["summary"] == {"succeeded": 12, "failed": 0}
    assert len({consumer.id for consumer in CONSUMERS}) == 12
    assert Counter(consumer.credential_type for consumer in CONSUMERS) == {"secret": 3, "certificate": 3, "key": 3, "oauth_token": 3}
    for category in ("secret", "certificate", "key", "oauth_token"):
        assert len({item["fingerprint"] for item in first["results"] if item["credential_type"] == category}) == 3
    for old, new in zip(first["results"], second["results"]):
        assert (old["fingerprint"] != new["fingerprint"]) == (old["credential_type"] == "oauth_token")
        assert old["retrieved_at"] != new["retrieved_at"]
        assert old["retrieval_duration_ms"] >= 0
        assert len(old["fingerprint"]) == 64
    events = records(local_demo)
    assert len([event for event in events if event["event_type"] == "credential.retrieved"]) == 24
    assert len([event for event in events if event["event_type"] == "provider.credential.validated" and event["outcome"] == "success"]) == 24


def test_issuance_records_have_sources_ttls_and_correlate_with_retrieval(local_demo):
    result = run(CONSUMERS, trigger="issuance_test")
    issued = [event for event in records(local_demo) if event["event_type"] == "credential.issued" and event["asset_role"] == "business"]
    assert len(issued) == 12
    assert Counter(event["credential_type"] for event in issued) == {"secret": 3, "key": 3, "certificate": 3, "oauth_token": 3}
    assert {event["issuance_source"] for event in issued} == {"Azure Vault", "PostgreSQL DB", "Google OAuth"}
    expected = {"secret": 86400, "key": 604800, "certificate": 2592000, "oauth_token": 300}
    lookup = {event["issuance_id"]: event for event in issued}
    for event in issued:
        assert event["environment"] == "testing"
        assert event["source_simulated"] is True
        assert event["actual_issuer"] in {"local-demo-generator", local_demo.url}
        assert event["ttl_seconds"] == expected[event["credential_type"]]
        assert 0 < event["remaining_ttl_seconds"] <= event["ttl_seconds"]
        assert (datetime.fromisoformat(event["expires_at"]) - datetime.fromisoformat(event["issued_at"])).total_seconds() == event["ttl_seconds"]
        assert event["consumer_name"] and event["api_path"] and event["fingerprint"]
    for item in result["results"]:
        event = lookup[item["issuance_id"]]
        assert item["fingerprint"] == event["fingerprint"]
        assert item["issued_at"] == event["issued_at"] and item["expires_at"] == event["expires_at"]
        assert item["issuance_source"] == event["issuance_source"]
    run(CONSUMERS, trigger="second_issuance_test")
    issued_again = [event for event in records(local_demo) if event["event_type"] == "credential.issued"]
    assert len(issued_again) == 15  # Nine original assets; six independently issued OAuth tokens.
    assert len({event["issuance_id"] for event in issued_again}) == 15


def test_legacy_issuance_backfill_preserves_assets_and_original_creation_time(template, tmp_path):
    root = tmp_path / "legacy"
    shutil.copytree(template, root)
    (root / "issuance.json").unlink()
    legacy = json.dumps({"event_type": "legacy.event", "preserve": True}) + "\n"
    (root / "ecomm-demo.jsonl").write_text(legacy)
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir() if path.name != "ecomm-demo.jsonl"}
    initialize(root)
    assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in before.items())
    assert (root / "ecomm-demo.jsonl").read_text().startswith(legacy)
    events = [event for event in records(type("Provider", (), {"root": root})()) if event["event_type"] == "credential.issued"]
    original = datetime.fromisoformat(json.loads((root / "manifest.json").read_text())["created_at"]).replace(microsecond=0)
    assert len(events) == 9
    assert all(event["historical_record"] and event["issuance_time_origin"] == "manifest_backfill" for event in events)
    assert all(datetime.fromisoformat(event["issued_at"]) == original for event in events)
    first_log = (root / "ecomm-demo.jsonl").read_bytes()
    initialize(root)
    assert (root / "ecomm-demo.jsonl").read_bytes() == first_log


def test_replaying_issuance_to_a_new_log_does_not_reset_ttl(template, tmp_path):
    root = tmp_path / "replay"
    shutil.copytree(template, root)
    original = json.loads((root / "issuance.json").read_text())
    (root / "ecomm-demo.jsonl").unlink()
    ensure_issuances(root)
    assert json.loads((root / "issuance.json").read_text()) == original
    events = [json.loads(line) for line in (root / "ecomm-demo.jsonl").read_text().splitlines()]
    assert len(events) == 9
    assert all(event["historical_record"] and event["issuance_record_reason"] == "log_replay" for event in events)


def test_legacy_backfill_does_not_attribute_replacement_material_to_original_issuance(template, tmp_path):
    root = tmp_path / "legacy-replaced"
    shutil.copytree(template, root)
    original = json.loads((root / "issuance.json").read_text())["credentials"]["catalog-secret"]
    (root / "issuance.json").unlink()
    (root / "catalog-api-secret.txt").write_text("replacement-before-backfill")
    entries = ensure_issuances(root)
    assert entries["catalog-secret"]["fingerprint"] == original["fingerprint"]
    assert entries["catalog-secret"]["issuance_id"] == original["issuance_id"]


def test_replacement_material_has_unknown_issuance_without_a_fabricated_record(local_demo):
    (local_demo.root / "catalog-api-secret.txt").write_text("unregistered-canary-value")
    result = invoke("catalog-secret")["results"][0]
    assert result["issuance_record_status"] == "fingerprint_mismatch"
    assert result["issuance_id"] is None and result["issued_at"] is None and result["ttl_seconds"] is None
    assert len([event for event in records(local_demo) if event["event_type"] == "credential.issued"]) == 9


def test_expired_static_issuance_blocks_retrieval_and_target_use(local_demo):
    path = local_demo.root / "issuance.json"
    document = json.loads(path.read_text())
    expiry = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    document["credentials"]["catalog-secret"]["expires_at"] = expiry
    path.write_text(json.dumps(document))
    with patch("demo.runtime.requests.post") as post:
        result = invoke("catalog-secret")["results"][0]
    post.assert_not_called()
    assert result["status"] == "failure" and result["remaining_ttl_seconds"] == 0
    local_demo.issuances["catalog-secret"]["expires_at"] = expiry
    response = requests.post(local_demo.url + "/targets/catalog-secret", json={"payload": {}},
                             headers={"X-API-Key": local_demo.references["catalog-secret"]["expected_secret"]},
                             verify=str(local_demo.root / "ca.pem"), timeout=5)
    assert response.status_code == 403


@pytest.mark.parametrize("identity", ["catalog-secret", "catalog-mtls", "catalog-signing", "promotions-oauth"])
def test_wrong_credentials_are_rejected_by_real_targets(local_demo, identity):
    root = local_demo.root
    if identity == "catalog-secret":
        (root / "catalog-api-secret.txt").write_text("canary-wrong-secret")
    elif identity == "catalog-mtls":
        for suffix in (".pem", ".key.pem"):
            shutil.copyfile(root / ("pricing-client-cert" + suffix), root / ("catalog-client-cert" + suffix))
    elif identity == "catalog-signing":
        shutil.copyfile(root / "order-signing-key.key.pem", root / "catalog-signing-key.key.pem")
    else:
        path = root / "promotions-oauth.client.json"
        client = json.loads(path.read_text())
        client["client_secret"] = "canary-wrong-oauth-secret"
        path.write_text(json.dumps(client))
    result = invoke(identity)
    assert result["summary"]["failed"] == 1
    assert result["results"][0]["error_code"] in {"CREDENTIAL_UNAVAILABLE", "CREDENTIAL_OPERATION_FAILED"}
    assert "canary-wrong" not in json.dumps(result) + (root / "ecomm-demo.jsonl").read_text()


def test_expired_certificate_and_mismatched_key_fail_retrieval(local_demo):
    root = local_demo.root
    path = root / "catalog-client-cert.pem"
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    ca = x509.load_pem_x509_certificate((root / "ca.pem").read_bytes())
    key = serialization.load_pem_private_key((root / "ca.key.pem").read_bytes(), None)
    builder = (x509.CertificateBuilder().subject_name(certificate.subject).issuer_name(ca.subject)
               .public_key(certificate.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(datetime.now(timezone.utc) - timedelta(days=2))
               .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1)))
    for extension in certificate.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    path.write_bytes(builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    assert invoke("catalog-mtls")["results"][0]["error_code"] == "CREDENTIAL_UNAVAILABLE"
    shutil.copyfile(root / "pricing-client-cert.key.pem", root / "catalog-client-cert.key.pem")
    assert invoke("catalog-mtls")["results"][0]["error_code"] == "CREDENTIAL_UNAVAILABLE"


@pytest.mark.parametrize("change", ["expired", "audience", "scope", "subject", "unsigned"])
def test_oauth_resource_rejects_invalid_tokens(local_demo, change):
    reference = local_demo.references["promotions-oauth"]
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"iss": local_demo.url, "sub": "promotions-oauth", "aud": reference["audience"],
              "scope": reference["scope"], "iat": now, "exp": now + 300, "jti": "test"}
    if change == "expired": claims["exp"] = now - 60
    if change == "audience": claims["aud"] = "other-audience"
    if change == "scope": claims["scope"] = "other:read"
    if change == "subject": claims["sub"] = "fulfillment-oauth"
    token = jwt.encode(claims, None, algorithm="none") if change == "unsigned" else local_demo.encode(claims)
    response = requests.post(local_demo.url + "/targets/promotions-oauth", json={"payload": {}},
                             headers={"Authorization": "Bearer " + token}, verify=str(local_demo.root / "ca.pem"), timeout=5)
    assert response.status_code == 403
    assert token not in (local_demo.root / "ecomm-demo.jsonl").read_text()


def test_missing_asset_and_provider_outage_have_safe_metadata(local_demo, settings):
    (local_demo.root / "catalog-api-secret.txt").unlink()
    result = invoke("catalog-secret")["results"][0]
    assert result["fingerprint"] is None and result["retrieved_at"] is None
    assert result["error_code"] == "CREDENTIAL_UNAVAILABLE"
    with patch("demo.runtime.requests.post", side_effect=requests.ConnectionError("canary-private-exception")):
        assert invoke("catalog-signing")["results"][0]["error_code"] == "CREDENTIAL_OPERATION_FAILED"
    assert "canary-private-exception" not in (local_demo.root / "ecomm-demo.jsonl").read_text()


def test_logs_and_results_never_include_raw_credential_material(local_demo):
    tokens = []
    post = requests.post
    def capture(*args, **kwargs):
        response = post(*args, **kwargs)
        if args[0].endswith("/token"):
            tokens.append(response.json()["access_token"])
        return response
    with patch("demo.runtime.requests.post", side_effect=capture):
        result = run(CONSUMERS, trigger="test")
    logger = logging.getLogger("demo-canary")
    handler = audit.SafeLogHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.error("Authorization: Bearer %s", tokens[0])
    finally:
        logger.removeHandler(handler)
    combined = json.dumps(result) + (local_demo.root / "ecomm-demo.jsonl").read_text()
    values = [*tokens, "BEGIN PRIVATE KEY", json.loads((local_demo.root / "bootstrap.json").read_text())["web_client_secret"]]
    values.extend((local_demo.root / f"{consumer.credential_name}.txt").read_text() for consumer in CONSUMERS if consumer.credential_type == "secret")
    assert all(value not in combined for value in values)


def test_concurrent_runs_have_complete_correlated_json_lines(local_demo):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: invoke("catalog-secret", "catalog-signing", "promotions-oauth"), range(8)))
    assert all(result["summary"] == {"succeeded": 3, "failed": 0} for result in results)
    events = records(local_demo)
    assert all(event["environment"] == "testing" for event in events)
    assert len({event["event_id"] for event in events}) == len(events)
    used = [event for event in events if event["event_type"] == "credential.used"]
    assert Counter(event["run_id"] for event in used) == {result["run_id"]: 3 for result in results}


def test_unwritable_audit_fails_before_any_credential_operation(local_demo, settings):
    settings.DEMO_LOG_PATH = local_demo.root / "missing-directory" / "log.jsonl"
    with patch("demo.runtime.requests.post") as post:
        result = invoke("catalog-secret")
    post.assert_not_called()
    assert result["results"][0]["error_code"] == "AUDIT_UNAVAILABLE"


@pytest.fixture
def buyer(local_demo, db):
    user = get_user_model().objects.create_user(username="demo-test", email="demo-test@example.test")
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(user, backend="allauth.account.auth_backends.AuthenticationBackend")
    token = client.get("/api/session/").json()["csrf_token"]
    return client, token


def test_environment_is_shared_by_provider_requests_credential_operations_and_failures(local_demo, buyer, monkeypatch):
    client, csrf = buyer
    before = len(records(local_demo))
    monkeypatch.setenv("ECOMM_DEMO_ENVIRONMENT", "staging")
    response = client.post("/api/demo/run/", {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.json()["summary"] == {"succeeded": 12, "failed": 0}
    (local_demo.root / "catalog-api-secret.txt").write_text("environment-failure-canary")
    response = client.post("/api/demo/services/catalog-secret/run/", {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 503
    events = records(local_demo)[before:]
    assert all(event["environment"] == "staging" for event in events)
    assert {event["event_type"] for event in events} >= {
        "credential.issued", "credential.retrieved", "credential.used", "credential.failed",
        "provider.token.issued", "provider.request.completed", "http.request.completed",
    }


def test_manual_apis_require_login_and_csrf_and_batch_reports_failures(local_demo, buyer):
    anonymous = APIClient(enforce_csrf_checks=True)
    assert anonymous.post("/api/demo/run/", {}, format="json").status_code == 403
    client, csrf = buyer
    assert client.post("/api/demo/run/", {}, format="json").status_code == 403
    assert len(client.get("/api/demo/services/").json()["services"]) == 12
    response = client.post("/api/demo/run/", {"credential_type": "certificate"}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.json()["summary"] == {"succeeded": 3, "failed": 0}
    (local_demo.root / "catalog-api-secret.txt").unlink()
    response = client.post("/api/demo/run/", {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 200
    assert response.json()["summary"] == {"succeeded": 11, "failed": 1}
    response = client.post("/api/demo/services/catalog-secret/run/", {}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 503 and response.json()["run_id"]
    assert client.post("/api/demo/run/", {"credential_type": "invalid"}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code == 400


def test_cart_allows_anonymous_and_empty_but_requires_csrf(local_demo, db):
    client = APIClient(enforce_csrf_checks=True)
    assert client.post("/api/demo/cart/", {"items": []}, format="json").status_code == 403
    csrf = client.get("/api/session/").json()["csrf_token"]
    response = client.post("/api/demo/cart/", {"items": []}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 200 and response.json()["summary"]["succeeded"] == 3
    assert client.post("/api/demo/cart/", {"items": [{"product_id": 99999, "quantity": 1}]}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code == 400


def test_shopping_triggers_and_failed_checkout_never_persists_order(local_demo, buyer):
    client, csrf = buyer
    product = Product.objects.create(name="Mug", description="Demo", category="Home", artwork="mug", price="1.00")
    assert client.get("/api/products/").status_code == 200
    assert client.get("/api/orders/").status_code == 200
    (local_demo.root / "checkout-api-secret.txt").write_text("wrong")
    response = client.post("/api/orders/", {"items": [{"product_id": product.pk, "quantity": 1}]}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 503 and response.json()["request_id"]
    assert Order.objects.count() == 0
    restored = local_demo.references["checkout-secret"]["expected_secret"]
    (local_demo.root / "checkout-api-secret.txt").write_text(restored)
    response = client.post("/api/orders/", {"items": [{"product_id": product.pk, "quantity": 1}]}, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 201 and Order.objects.count() == 1
    by_trigger = {}
    for event in records(local_demo):
        if event["event_type"] == "credential.used":
            by_trigger.setdefault(event["trigger"], set()).add(event["consumer_id"])
    assert by_trigger["products"] == {"catalog-secret", "catalog-mtls", "catalog-signing"}
    assert by_trigger["orders"] == {"tracking-mtls", "receipt-signing", "notifications-oauth"}
    assert by_trigger["checkout"] == {"checkout-secret", "order-signing", "fulfillment-oauth"}


def test_demo_disabled_and_non_loopback_requests_are_rejected(local_demo, settings, db):
    client = APIClient()
    assert client.get("/api/demo/services/", REMOTE_ADDR="192.0.2.1").status_code == 403
    settings.DEMO_ENABLED = False
    assert client.get("/api/demo/services/").status_code == 404


def test_local_oidc_login_uses_code_pkce_and_signature_verification(local_demo, settings, db):
    settings.SOCIALACCOUNT_ADAPTER = "demo.adapter.DemoSocialAccountAdapter"
    bootstrap = local_demo.bootstrap
    settings.SOCIALACCOUNT_PROVIDERS = {"openid_connect": {"OAUTH_PKCE_ENABLED": True, "APPS": [{
        "provider_id": "shop", "name": "Local Demo", "client_id": "everyday-web", "secret": bootstrap["web_client_secret"],
        "settings": {"server_url": local_demo.url + "/demo-provider", "oauth_pkce_enabled": True,
                     "fetch_userinfo": False, "token_auth_method": "client_secret_basic"},
    }]}}
    host = urlsplit(local_demo.frontend_origin).netloc
    client = APIClient(enforce_csrf_checks=True)
    csrf = client.get("/api/session/", HTTP_HOST=host).json()["csrf_token"]
    start = client.post("/accounts/oidc/shop/login/", {"csrfmiddlewaretoken": csrf}, HTTP_HOST=host)
    assert start.status_code == 302
    parsed = urlsplit(start["Location"])
    with requests.Session() as browser:
        browser.verify = str(local_demo.root / "ca.pem")
        consent = browser.get(local_demo.url + parsed.path + "?" + parsed.query, timeout=5)
        assert consent.status_code == 200
        approval = re.search(r'name="approval" value="([^"]+)"', consent.text).group(1)
        redirect = browser.post(local_demo.url + "/demo-provider/authorize", data={"approval": approval}, timeout=5, allow_redirects=False)
        assert redirect.status_code == 302
        assert browser.post(local_demo.url + "/demo-provider/authorize", data={"approval": approval}, timeout=5).status_code == 403
    callback = urlsplit(redirect.headers["Location"])
    response = client.get(callback.path + "?" + callback.query, HTTP_HOST=host)
    assert response.status_code == 302
    assert client.get("/api/session/", HTTP_HOST=host).json()["user"]["email"] == "demo.buyer@example.test"
    assert client.get(callback.path + "?" + callback.query, HTTP_HOST=host).status_code == 401
    log = (local_demo.root / "ecomm-demo.jsonl").read_text()
    assert approval not in log and callback.query not in log
    web_issuances = [event for event in records(local_demo) if event["event_type"] == "credential.issued" and event["asset_role"] == "infrastructure"]
    assert {event["credential_name"] for event in web_issuances} == {"website-id-token", "website-access-token"}
    assert all(event["ttl_seconds"] == 300 and event["source_simulated"] for event in web_issuances)


def test_demo_settings_ignore_real_vault_and_use_separate_database(template):
    import subprocess
    import sys
    env = {**os.environ, "ECOMM_DEMO_MODE": "true", "ECOMM_DEMO_DIR": str(template),
           "AZURE_KEY_VAULT_URL": "https://should-never-contact.vault.azure.net", "OIDC_CLIENT_ID": ""}
    result = subprocess.run([sys.executable, "-B", "-c", "from config import settings as s; assert s.DATABASES['default']['NAME'].parent == s.DEMO_ASSET_DIR; assert s.OIDC_CLIENT_ID == 'everyday-web'; assert not s.DEBUG; print('isolated')"],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "isolated"


def test_run_demo_command_starts_both_servers_with_isolated_database(template, tmp_path):
    import signal
    import socket
    import subprocess
    import sys
    import time
    root = tmp_path / "command-demo"
    shutil.copytree(template, root)
    def free_port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    backend_port, provider_port = free_port(), free_port()
    env = {**os.environ, "DJANGO_SETTINGS_MODULE": "config.settings", "ECOMM_DEMO_MODE": "true",
           "ECOMM_DEMO_DIR": str(root), "ECOMM_DEMO_PROVIDER_PORT": str(provider_port), "PYTHONUNBUFFERED": "1"}
    process = subprocess.Popen([sys.executable, "-B", "manage.py", "run_demo", "--port", str(backend_port)],
                               cwd=Path(__file__).resolve().parents[1], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail("Demo command exited: " + stdout + stderr)
            try:
                response = requests.get(f"http://127.0.0.1:{backend_port}/api/session/", timeout=1)
                if response.status_code == 200:
                    break
            except requests.ConnectionError:
                pass
            assert time.monotonic() < deadline, "Demo command did not start"
            time.sleep(0.1)
        assert response.json()["demo_enabled"] is True
        assert response.json()["oauth_configured"] is True
        catalog = requests.get(f"http://127.0.0.1:{backend_port}/api/products/", timeout=10)
        assert catalog.status_code == 200 and len(catalog.json()) == 6
        assert (root / "db.sqlite3").exists()
        events = [json.loads(line) for line in (root / "ecomm-demo.jsonl").read_text().splitlines()]
        assert all(event["environment"] == "testing" for event in events)
        assert {event["event_type"] for event in events} >= {"application.starting", "provider.started", "credential.used", "http.request.completed"}
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
