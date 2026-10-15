import os

# Test values only; environment overrides keep local credentials out of tests.
os.environ["DJANGO_SECRET_KEY"] = "test-only-django-secret-" + "x" * 64
os.environ["OIDC_CLIENT_ID"] = "test-client"
os.environ["OIDC_CLIENT_SECRET"] = "test-only-client-secret"
os.environ["OIDC_SERVER_URL"] = "http://127.0.0.1:9999"
os.environ["DJANGO_DEBUG"] = "true"
os.environ["AZURE_KEY_VAULT_URL"] = ""  # Tests never contact the developer's vault.
os.environ["ECOMM_DEMO_MODE"] = "false"  # Demo tests opt in with isolated asset directories.
os.environ["ECOMM_DEMO_ENVIRONMENT"] = "testing"
