import os
import json
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv
from .key_vault import load_application_secrets

BASE_DIR = Path(__file__).resolve().parent.parent
DEMO_ENABLED = os.getenv("ECOMM_DEMO_MODE", "false").lower() == "true"
if DEMO_ENABLED:
    from demo.audit import environment_name
    DEMO_ENVIRONMENT = environment_name()
DEMO_ASSET_DIR = Path(os.getenv("ECOMM_DEMO_DIR", str(BASE_DIR / ".demo"))).resolve()
DEMO_LOG_PATH = DEMO_ASSET_DIR / "ecomm-demo.jsonl"
DEMO_PROVIDER_PORT = int(os.getenv("ECOMM_DEMO_PROVIDER_PORT", "9443"))
DEMO_PROVIDER_URL = f"https://127.0.0.1:{DEMO_PROVIDER_PORT}"
DEMO_FRONTEND_ORIGIN = os.getenv("ECOMM_DEMO_FRONTEND_ORIGIN", "http://127.0.0.1:5173")
if not DEMO_ENABLED:
    load_dotenv(BASE_DIR / ".env")
DEBUG = os.getenv("DJANGO_DEBUG", "true").lower() == "true"
if DEMO_ENABLED:
    try:
        _bootstrap = json.loads((DEMO_ASSET_DIR / "bootstrap.json").read_text())
        _application_secrets = {"DJANGO_SECRET_KEY": _bootstrap["django_secret_key"], "OIDC_CLIENT_SECRET": _bootstrap["web_client_secret"]}
        del _bootstrap
    except (OSError, ValueError, KeyError):
        raise ImproperlyConfigured("Initialize local demo assets with python scripts/init_demo.py first.") from None
    DEBUG = False
else:
    _application_secrets = load_application_secrets()
SECRET_KEY = _application_secrets["DJANGO_SECRET_KEY"]
if not SECRET_KEY or len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must contain at least 50 characters in the configured secret source.")

ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
CSRF_TRUSTED_ORIGINS = os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles",
    "rest_framework", "allauth", "allauth.account", "allauth.socialaccount",
    "allauth.socialaccount.providers.openid_connect", "shop",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware", "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware", "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware", "django.contrib.messages.middleware.MessageMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
AUTHENTICATION_BACKENDS = ["allauth.account.auth_backends.AuthenticationBackend"]
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
}
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*"]
ACCOUNT_EMAIL_VERIFICATION = "none"
SOCIALACCOUNT_ONLY = True
SOCIALACCOUNT_STORE_TOKENS = False
SOCIALACCOUNT_LOGIN_ON_GET = False
OIDC_SERVER_URL = DEMO_PROVIDER_URL + "/demo-provider" if DEMO_ENABLED else os.getenv("OIDC_SERVER_URL", "https://accounts.google.com")
OIDC_CLIENT_ID = "everyday-web" if DEMO_ENABLED else os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = _application_secrets["OIDC_CLIENT_SECRET"]
del _application_secrets
OIDC_PROVIDER_NAME = os.getenv("OIDC_PROVIDER_NAME", "Google")
if bool(OIDC_CLIENT_ID) != bool(OIDC_CLIENT_SECRET):
    raise ImproperlyConfigured("Set both OIDC_CLIENT_ID and OIDC_CLIENT_SECRET.")
if not DEBUG and not OIDC_SERVER_URL.startswith("https://"):
    raise ImproperlyConfigured("The OAuth provider must use HTTPS when DJANGO_DEBUG=false.")
SOCIALACCOUNT_PROVIDERS = {"openid_connect": {
    "OAUTH_PKCE_ENABLED": True,
    "APPS": [{
        "provider_id": "shop", "name": OIDC_PROVIDER_NAME,
        "client_id": OIDC_CLIENT_ID, "secret": OIDC_CLIENT_SECRET,
        "settings": {
            "server_url": OIDC_SERVER_URL, "oauth_pkce_enabled": True,
            "fetch_userinfo": False, "token_auth_method": "client_secret_basic",
        },
    }],
}}
LOGIN_REDIRECT_URL = "/"
ACCOUNT_LOGOUT_REDIRECT_URL = "/"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

if DEMO_ENABLED:
    ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]
    CSRF_TRUSTED_ORIGINS = [DEMO_FRONTEND_ORIGIN]
    DATABASES["default"]["NAME"] = DEMO_ASSET_DIR / "db.sqlite3"
    SESSION_COOKIE_SECURE = False  # Explicitly loopback HTTP browser traffic only.
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_NAME = "ecomm_demo_sessionid"
    CSRF_COOKIE_NAME = "ecomm_demo_csrftoken"
    OIDC_SERVER_URL = DEMO_PROVIDER_URL + "/demo-provider"
    OIDC_CLIENT_ID = "everyday-web"
    OIDC_PROVIDER_NAME = "Local Demo"
    SOCIALACCOUNT_PROVIDERS["openid_connect"]["APPS"][0].update(
        client_id=OIDC_CLIENT_ID, name=OIDC_PROVIDER_NAME)
    SOCIALACCOUNT_PROVIDERS["openid_connect"]["APPS"][0]["settings"]["server_url"] = OIDC_SERVER_URL
    SOCIALACCOUNT_ADAPTER = "demo.adapter.DemoSocialAccountAdapter"
    MIDDLEWARE.append("demo.middleware.DemoAuditMiddleware")
    LOGGING = {
        "version": 1, "disable_existing_loggers": False,
        "handlers": {"demo": {"class": "demo.audit.SafeLogHandler"}},
        "root": {"handlers": ["demo"], "level": "INFO"},
        "loggers": {name: {"handlers": [], "propagate": True, "level": "INFO"}
                    for name in ("django", "django.server", "django.request", "urllib3")},
    }
