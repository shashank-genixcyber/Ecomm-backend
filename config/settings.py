import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv
from .key_vault import load_application_secrets

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DEBUG = os.getenv("DJANGO_DEBUG", "true").lower() == "true"
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
OIDC_SERVER_URL = os.getenv("OIDC_SERVER_URL", "https://accounts.google.com")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
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
