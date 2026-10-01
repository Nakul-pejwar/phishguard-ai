import os

from .base import *  # noqa: F403

DEBUG = False

SECRET_KEY = os.getenv("SECRET_KEY", "prod-insecure-phishguard-production-fallback-key-must-be-configured-via-env-vars-32chars")

ALLOWED_HOSTS = [host.strip() for host in os.getenv("ALLOWED_HOSTS", "api.phishguard.ai,localhost,127.0.0.1").split(",") if host.strip()]

CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    origin.strip() for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if origin.strip()
]

# Reverse Proxy & SSL Configuration (For Caddy / Nginx)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

if os.getenv("SECURE_SSL_REDIRECT", "True") == "True":
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
