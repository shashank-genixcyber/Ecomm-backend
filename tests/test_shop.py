import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.utils import timezone
from rest_framework.test import APIClient

from shop.models import Order, Product

pytestmark = pytest.mark.django_db
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def product():
    return Product.objects.create(name="Mug", description="A mug", category="Home", artwork="mug", price="690.00")


@pytest.fixture
def user():
    return get_user_model().objects.create_user(username="buyer", email="buyer@example.com")


def authenticated_client(user):
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(user, backend="allauth.account.auth_backends.AuthenticationBackend")
    csrf = client.get("/api/session/").json()["csrf_token"]
    return client, csrf


def test_catalog_is_public_and_session_exposes_no_secrets(product):
    client = APIClient()
    assert client.get("/api/products/").json()[0]["price"] == "690.00"
    response = client.get("/api/session/")
    assert response.json()["user"] is None
    assert response.json()["csrf_token"]
    assert "no-store" in response["Cache-Control"]
    assert "test-only-client-secret" not in response.content.decode()
    assert "test-only-django-secret" not in response.content.decode()
    assert response.cookies["csrftoken"]["httponly"]


def test_orders_require_login_and_reject_bearer_id_tokens(product):
    client = APIClient()
    assert client.get("/api/orders/").status_code == 403
    assert client.post("/api/orders/", {"items": [{"product_id": product.id, "quantity": 1}]}, format="json").status_code == 403
    assert client.get("/api/orders/", HTTP_AUTHORIZATION="Bearer fake-id-token").status_code == 403


def test_checkout_uses_server_price_and_orders_are_private(user, product):
    client, csrf = authenticated_client(user)
    response = client.post("/api/orders/", {
        "items": [{"product_id": product.id, "quantity": 2, "price": "0.01"}], "total": "0.02",
    }, format="json", HTTP_X_CSRFTOKEN=csrf)
    assert response.status_code == 201
    assert response.json()["total"] == "1380.00"
    assert response.json()["items"][0]["price"] == "690.00"
    assert len(client.get("/api/orders/").json()) == 1
    other = get_user_model().objects.create_user(username="other", email="other@example.com")
    other_client, _ = authenticated_client(other)
    assert other_client.get("/api/orders/").json() == []


@pytest.mark.parametrize("quantity", [0, -1, 21, 1.5, "invalid"])
def test_invalid_quantity_cannot_create_order(user, product, quantity):
    client, csrf = authenticated_client(user)
    assert client.post("/api/orders/", {"items": [{"product_id": product.id, "quantity": quantity}]}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code == 400
    assert Order.objects.count() == 0


@pytest.mark.parametrize("items", [[], [{"product_id": 9999, "quantity": 1}], [{"product_id": 1, "quantity": 1}] * 2])
def test_invalid_cart_cannot_create_order(user, items):
    client, csrf = authenticated_client(user)
    assert client.post("/api/orders/", {"items": items}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code == 400
    assert Order.objects.count() == 0


def test_checkout_and_logout_require_csrf(user, product):
    client, _ = authenticated_client(user)
    assert client.post("/api/orders/", {"items": [{"product_id": product.id, "quantity": 1}]}, format="json").status_code == 403
    assert client.post("/api/logout/").status_code == 403
    assert client.post("/api/logout/", HTTP_X_CSRFTOKEN="invalid").status_code == 403
    assert client.get("/api/session/").json()["user"] is not None


def test_logout_invalidates_the_session(user):
    client, csrf = authenticated_client(user)
    old_cookie = client.cookies["sessionid"].value
    assert client.post("/api/logout/", HTTP_X_CSRFTOKEN=csrf).status_code == 200
    assert client.get("/api/session/").json()["user"] is None
    client.cookies["sessionid"] = old_cookie
    assert client.get("/api/orders/").status_code == 403


def test_tampered_and_expired_session_cookies_are_rejected(user):
    client, _ = authenticated_client(user)
    session_key = client.cookies["sessionid"].value
    client.cookies["sessionid"] = "tampered-session-cookie"
    assert client.get("/api/orders/").status_code == 403
    client.cookies["sessionid"] = session_key
    Session.objects.filter(session_key=session_key).update(expire_date=timezone.now())
    assert client.get("/api/orders/").status_code == 403


@pytest.mark.parametrize("secret", ["", "too-short"])
def test_missing_or_weak_backend_secret_fails_startup(secret):
    result = subprocess.run([sys.executable, "manage.py", "check"], cwd=ROOT, env={**os.environ, "DJANGO_SECRET_KEY": secret}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "DJANGO_SECRET_KEY" in result.stderr


def test_production_cookie_settings_and_insecure_provider_rejection():
    env = {**os.environ, "DJANGO_DEBUG": "false", "OIDC_SERVER_URL": "https://accounts.google.com"}
    result = subprocess.run([sys.executable, "-c", "from config import settings; import json; print(json.dumps([settings.SESSION_COOKIE_SECURE, settings.CSRF_COOKIE_SECURE, settings.SESSION_COOKIE_HTTPONLY]))"], cwd=ROOT, env=env, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == [True, True, True]
    result = subprocess.run([sys.executable, "manage.py", "check"], cwd=ROOT, env={**env, "OIDC_SERVER_URL": "http://example.com"}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "must use HTTPS" in result.stderr


def test_secrets_are_not_in_frontend_source_or_built_files():
    for directory in (ROOT / "frontend" / "src", ROOT / "frontend" / "dist"):
        for path in directory.rglob("*"):
            if path.is_file():
                text = path.read_text(errors="ignore")
                assert "test-only-client-secret" not in text
                assert "test-only-django-secret" not in text
                assert "VITE_OIDC_CLIENT_SECRET" not in text

