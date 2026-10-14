from datetime import datetime, timedelta, timezone
import runpy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
import traceback

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ServiceRequestError
from django.core.exceptions import ImproperlyConfigured
import pytest

from config import key_vault


@pytest.fixture
def vault(monkeypatch):
    for key, value in {
        "AZURE_KEY_VAULT_URL": "https://argus-nhi.vault.azure.net",
        "AZURE_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "AZURE_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
        "AZURE_CLIENT_SECRET": "synthetic-azure-bootstrap-secret",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DJANGO_SECRET_KEY_NAME", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_SECRET_NAME", raising=False)
    secrets = {
        name: SimpleNamespace(value=value, properties=SimpleNamespace(enabled=True, expires_on=None, not_before=None))
        for name, value in {
            "django-secret-key": "synthetic-vault-django-key-" + "x" * 64,
            "oidc-client-secret": "synthetic-vault-oidc-secret",
        }.items()
    }
    credential_factory = MagicMock()
    client_factory = MagicMock()
    client = client_factory.return_value.__enter__.return_value
    client.get_secret.side_effect = lambda name, **kwargs: secrets[name]
    monkeypatch.setattr(key_vault, "ClientSecretCredential", credential_factory)
    monkeypatch.setattr(key_vault, "SecretClient", client_factory)
    return SimpleNamespace(secrets=secrets, client=client, client_factory=client_factory,
        credential_factory=credential_factory)


def test_startup_uses_vault_values_for_django_and_allauth(vault, monkeypatch):
    monkeypatch.setenv("DJANGO_SECRET_KEY", "unused-local-value")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "unused-local-value")
    settings = runpy.run_path(str(Path(__file__).resolve().parents[1] / "config/settings.py"), run_name="config.settings")
    assert settings["SECRET_KEY"] == vault.secrets["django-secret-key"].value
    assert settings["OIDC_CLIENT_SECRET"] == vault.secrets["oidc-client-secret"].value
    assert settings["SOCIALACCOUNT_PROVIDERS"]["openid_connect"]["APPS"][0]["secret"] == settings["OIDC_CLIENT_SECRET"]
    assert [call.args[0] for call in vault.client.get_secret.call_args_list] == ["django-secret-key", "oidc-client-secret"]
    assert vault.credential_factory.call_args.kwargs["client_secret"] == "synthetic-azure-bootstrap-secret"
    assert vault.client_factory.call_args.kwargs["logging_enable"] is False
    vault.client.set_secret.assert_not_called()
    vault.client.begin_delete_secret.assert_not_called()
    vault.client_factory.return_value.__exit__.assert_called_once()


def test_local_mode_does_not_initialize_azure(vault, monkeypatch):
    monkeypatch.setenv("AZURE_KEY_VAULT_URL", "")
    monkeypatch.setenv("DJANGO_SECRET_KEY", "synthetic-local-key")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "synthetic-local-oidc")
    assert key_vault.load_application_secrets() == {"DJANGO_SECRET_KEY": "synthetic-local-key", "OIDC_CLIENT_SECRET": "synthetic-local-oidc"}
    vault.credential_factory.assert_not_called()
    vault.client_factory.assert_not_called()


def test_configurable_secret_names(vault, monkeypatch):
    monkeypatch.setenv("DJANGO_SECRET_KEY_NAME", "custom-django-key")
    monkeypatch.setenv("OIDC_CLIENT_SECRET_NAME", "custom-oidc-key")
    vault.secrets["custom-django-key"] = vault.secrets["django-secret-key"]
    vault.secrets["custom-oidc-key"] = vault.secrets["oidc-client-secret"]
    key_vault.load_application_secrets()
    assert [call.args[0] for call in vault.client.get_secret.call_args_list] == ["custom-django-key", "custom-oidc-key"]


@pytest.mark.parametrize("key,value", [
    ("AZURE_TENANT_ID", ""), ("AZURE_CLIENT_ID", ""), ("AZURE_CLIENT_SECRET", " "),
    ("AZURE_KEY_VAULT_URL", "https://example.com"),
    ("AZURE_KEY_VAULT_URL", "http://argus-nhi.vault.azure.net"),
    ("AZURE_KEY_VAULT_URL", "https://argus-nhi.vault.azure.net/secrets/foo"),
    ("DJANGO_SECRET_KEY_NAME", "DJANGO_SECRET_KEY"),
    ("OIDC_CLIENT_SECRET_NAME", ""),
    ("OIDC_CLIENT_SECRET_NAME", "DJANGO-SECRET-KEY"),
])
def test_invalid_configuration_fails_before_azure_request(vault, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(ImproperlyConfigured):
        key_vault.load_application_secrets()
    vault.client_factory.assert_not_called()


@pytest.mark.parametrize("error", [
    ResourceNotFoundError("synthetic-private-error"),
    HttpResponseError("synthetic-private-error", status_code=403),
    HttpResponseError("synthetic-private-error", status_code=429),
    ServiceRequestError("synthetic-private-error"),
])
def test_azure_errors_are_sanitized_and_never_fall_back(vault, monkeypatch, error, caplog):
    monkeypatch.setenv("DJANGO_SECRET_KEY", "synthetic-local-fallback" * 3)
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "synthetic-local-fallback")
    vault.client.get_secret.side_effect = error
    with pytest.raises(ImproperlyConfigured) as caught:
        key_vault.load_application_secrets()
    output = "".join(traceback.format_exception(caught.type, caught.value, caught.tb)) + caplog.text
    assert "synthetic-private-error" not in output
    assert "synthetic-local-fallback" not in output
    assert "secret read permissions" in output


@pytest.mark.parametrize("name", ["django-secret-key", "oidc-client-secret"])
@pytest.mark.parametrize("invalid", ["empty", "disabled", "expired", "future"])
def test_unusable_secret_fails_startup(vault, name, invalid):
    secret = vault.secrets[name]
    if invalid == "empty":
        secret.value = " "
    elif invalid == "disabled":
        secret.properties.enabled = False
    elif invalid == "expired":
        secret.properties.expires_on = datetime.now(timezone.utc) - timedelta(minutes=1)
    elif invalid == "future":
        secret.properties.not_before = datetime.now(timezone.utc) + timedelta(minutes=1)
    with pytest.raises(ImproperlyConfigured):
        key_vault.load_application_secrets()


def test_weak_django_key_from_vault_is_rejected(vault):
    vault.secrets["django-secret-key"].value = "too-short"
    with pytest.raises(ImproperlyConfigured, match="at least 50 characters"):
        runpy.run_path(str(Path(__file__).resolve().parents[1] / "config/settings.py"), run_name="config.settings")
