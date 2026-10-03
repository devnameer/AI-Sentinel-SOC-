"""
Django settings — a thin layer over core.config (config.yaml + .env).

Nothing secret is hard-coded here. Security-relevant defaults are safe:
DEBUG off, explicit ALLOWED_HOSTS / CORS origins, optional bearer-token auth.
"""
from __future__ import annotations

import os
import secrets
import warnings
from urllib.parse import unquote, urlparse

from django.core.exceptions import ImproperlyConfigured

from core.config import get_config
from core.logs import build_logging_config

CFG = get_config()
PRODUCTION = CFG.app.environment == "production"


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# ── Core ───────────────────────────────────────────────────────────────────
SECRET_KEY = CFG.secrets.django_secret_key
if not SECRET_KEY:
    if PRODUCTION:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set in .env when APP_ENV=production")
    SECRET_KEY = secrets.token_urlsafe(50)  # ephemeral dev key (sessions are not used)
    warnings.warn("DJANGO_SECRET_KEY not set — using a random key for this run (fine for local dev).")

DEBUG = _env_bool("DJANGO_DEBUG", default=False) and not PRODUCTION
ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,backend")

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",          # required by DRF's AnonymousUser; no user accounts are created
    "rest_framework",
    "corsheaders",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "soc_platform.urls"
WSGI_APPLICATION = "soc_platform.wsgi.application"
TEMPLATES: list = []

# ── Database ───────────────────────────────────────────────────────────────
if CFG.database.engine == "postgres":
    if not CFG.secrets.database_url:
        raise ImproperlyConfigured("database.engine is 'postgres' but DATABASE_URL is not set in .env")
    url = urlparse(CFG.secrets.database_url)
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": url.path.lstrip("/"), "USER": unquote(url.username or ""),
        "PASSWORD": unquote(url.password or ""), "HOST": url.hostname or "localhost",
        "PORT": str(url.port or 5432), "CONN_MAX_AGE": 60,
        "OPTIONS": {"sslmode": os.environ.get("DATABASE_SSLMODE", "prefer")},
    }}
else:
    sqlite_path = CFG.path(CFG.database.sqlite_path)
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": str(sqlite_path),
                             "OPTIONS": {"timeout": 20}}}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = CFG.app.timezone
LANGUAGE_CODE = "en-us"

# ── REST framework ─────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["core.auth.BearerTokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["core.auth.TokenRequiredIfConfigured"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "EXCEPTION_HANDLER": "core.errors.api_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.ScopedRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "simulate": CFG.api.throttle.simulate,
        "ingest": CFG.api.throttle.ingest,
    },
    "UNAUTHENTICATED_USER": None,
}

# ── CORS / security headers ────────────────────────────────────────────────
# The Next.js frontend calls the API server-side (proxy route), so CORS is only
# needed for direct browser access during development.
CORS_ALLOWED_ORIGINS = _env_list("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
CORS_ALLOW_CREDENTIALS = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
if PRODUCTION:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = _env_bool("DJANGO_SECURE_SSL_REDIRECT", False)

# ── Logging ────────────────────────────────────────────────────────────────
LOGGING = build_logging_config(json_output=PRODUCTION or _env_bool("LOG_JSON"),
                               level=os.environ.get("LOG_LEVEL", "INFO"))
