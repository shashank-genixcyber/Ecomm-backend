from urllib.parse import parse_qs, urlencode, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
import requests
from rest_framework.test import APIClient
from allauth.socialaccount.models import SocialToken

from .provider import configure

pytestmark = pytest.mark.django_db


def start_login(client):
    csrf = client.get("/api/session/").json()["csrf_token"]
    response = client.post("/accounts/oidc/shop/login/", {"csrfmiddlewaretoken": csrf, "next": "/"})
    assert response.status_code == 302
    return response["Location"]


def callback_url(authorize_url):
    response = requests.get(authorize_url, allow_redirects=False, timeout=5)
    assert response.status_code == 302
    parsed = urlparse(response.headers["Location"])
    return parsed.path + "?" + parsed.query


def test_real_authorization_code_exchange_pkce_and_server_session(provider):
    client = APIClient(enforce_csrf_checks=True)
    authorize_url = start_login(client)
    params = parse_qs(urlparse(authorize_url).query)
    assert params["code_challenge_method"] == ["S256"]
    assert "openid" in params["scope"][0]
    assert provider.secret not in authorize_url
    response = client.get(callback_url(authorize_url))
    assert response.status_code == 302
    assert response["Location"] == "/"
    assert provider.used_pkce
    assert client.get("/api/session/").json()["user"]["email"] == "buyer@example.com"
    assert client.cookies["sessionid"]["httponly"]
    assert client.cookies["sessionid"]["samesite"] == "Lax"
    assert SocialToken.objects.count() == 0


@pytest.mark.parametrize("mode", ["expired", "tampered", "wrong_issuer", "wrong_audience", "missing_expiry", "missing_subject", "unsigned", "malformed"])
def test_invalid_id_tokens_cannot_sign_in(provider, mode):
    provider.mode = mode
    client = APIClient(enforce_csrf_checks=True)
    response = client.get(callback_url(start_login(client)))
    assert response.status_code == 401
    assert client.get("/api/session/").json()["user"] is None
    assert client.get("/api/orders/").status_code == 403
    assert SocialToken.objects.count() == 0


def test_state_tampering_prevents_token_exchange(provider):
    client = APIClient(enforce_csrf_checks=True)
    callback = callback_url(start_login(client))
    parsed = urlparse(callback)
    params = parse_qs(parsed.query)
    params["state"] = ["attacker-state"]
    response = client.get(parsed.path + "?" + urlencode(params, doseq=True))
    assert response.status_code == 401
    assert provider.token_requests == 0
    assert client.get("/api/session/").json()["user"] is None


def test_authorization_code_and_state_cannot_be_replayed(provider):
    client = APIClient(enforce_csrf_checks=True)
    callback = callback_url(start_login(client))
    assert client.get(callback).status_code == 302
    csrf = client.get("/api/session/").json()["csrf_token"]
    client.post("/api/logout/", HTTP_X_CSRFTOKEN=csrf)
    assert client.get(callback).status_code == 401
    assert provider.token_requests == 1
    assert client.get("/api/session/").json()["user"] is None


def test_pkce_mismatch_is_rejected(provider):
    client = APIClient(enforce_csrf_checks=True)
    authorize = urlparse(start_login(client))
    params = parse_qs(authorize.query)
    params["code_challenge"] = ["attacker-challenge"]
    callback = callback_url(authorize._replace(query=urlencode(params, doseq=True)).geturl())
    assert client.get(callback).status_code == 401
    assert not provider.used_pkce
    assert client.get("/api/session/").json()["user"] is None


def test_rotated_secret_rejects_old_credentials_and_accepts_new(provider, settings):
    provider.secret = "test-only-rotated-secret"
    client = APIClient(enforce_csrf_checks=True)
    assert client.get(callback_url(start_login(client))).status_code == 401
    assert client.get("/api/session/").json()["user"] is None
    configure(settings, provider)
    assert client.get(callback_url(start_login(client))).status_code == 302
    assert client.get("/api/session/").json()["user"] is not None


def test_signing_key_rotation_is_supported(provider):
    provider.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = APIClient(enforce_csrf_checks=True)
    assert client.get(callback_url(start_login(client))).status_code == 302
    assert client.get("/api/session/").json()["user"] is not None


def test_login_requires_post_and_csrf(provider):
    client = APIClient(enforce_csrf_checks=True)
    assert client.get("/accounts/oidc/shop/login/").status_code == 200
    assert client.post("/accounts/oidc/shop/login/").status_code == 403
    assert provider.token_requests == 0
