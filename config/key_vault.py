"""Read the application's two configuration secrets once, during Django startup."""
from datetime import datetime, timezone
import os
import re

from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables


@sensitive_variables()
def load_application_secrets():
    vault_url = os.getenv("AZURE_KEY_VAULT_URL", "").strip().rstrip("/")
    if not vault_url:
        # Preserve the original local-development setup when Azure is not enabled.
        return {key: os.getenv(key, "") for key in ("DJANGO_SECRET_KEY", "OIDC_CLIENT_SECRET")}
    if not re.fullmatch(r"https://[A-Za-z0-9-]+\.vault\.azure\.net", vault_url):
        raise ImproperlyConfigured("AZURE_KEY_VAULT_URL must be a public Azure HTTPS vault endpoint.")
    required = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
    if any(not os.getenv(key, "").strip() for key in required):
        raise ImproperlyConfigured("Key Vault requires AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (the secret Value).")
    names = {
        "DJANGO_SECRET_KEY": os.getenv("DJANGO_SECRET_KEY_NAME", "django-secret-key"),
        "OIDC_CLIENT_SECRET": os.getenv("OIDC_CLIENT_SECRET_NAME", "oidc-client-secret"),
    }
    if any(not re.fullmatch(r"[A-Za-z0-9-]{1,127}", name) for name in names.values()):
        raise ImproperlyConfigured("Key Vault secret names must contain only letters, digits and hyphens.")
    if len(set(name.lower() for name in names.values())) != len(names):
        raise ImproperlyConfigured("Django and OIDC must use separate Key Vault secrets.")
    try:
        with ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"], client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"], logging_enable=False,
            connection_timeout=5, read_timeout=15, retry_total=2,
        ) as credential, SecretClient(
            vault_url=vault_url, credential=credential, logging_enable=False,
            connection_timeout=5, read_timeout=15, retry_total=2,
        ) as client:
            values = {}
            for setting, name in names.items():
                secret = client.get_secret(name, logging_enable=False)
                properties = secret.properties
                now = datetime.now(timezone.utc)
                if (properties.enabled is False
                    or (properties.expires_on is not None and properties.expires_on <= now)
                    or (properties.not_before is not None and properties.not_before > now)
                    or not isinstance(secret.value, str) or not secret.value.strip()):
                    raise ImproperlyConfigured(f"The Key Vault secret for {setting} is empty, disabled or outside its validity period.")
                values[setting] = secret.value
            return values
    except (AzureError, OSError, ValueError):
        # SDK exception details may contain sensitive request/response content.
        # Configured Azure failures must never fall back to local secret values.
        raise ImproperlyConfigured(
            "Cannot read application secrets from Azure Key Vault. Check the Azure app credentials, "
            "secret names, secret read permissions and vault network access."
        ) from None
