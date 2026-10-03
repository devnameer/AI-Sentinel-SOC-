"""
Optional bearer-token authentication.

If ``SOC_API_TOKEN`` is set in .env, every API request (except the health check)
must send ``Authorization: Bearer <token>``. The Next.js frontend adds the
header server-side (see frontend/app/api/soc/[...path]/route.ts), so the token
is never shipped to the browser.

If the variable is empty the API is open — acceptable only on localhost. The
System Health page shows a warning in that case.
"""
from __future__ import annotations

import hmac

from rest_framework import authentication, exceptions, permissions

from core.config import get_config


class TokenUser:
    """Minimal authenticated principal (no Django user table needed)."""

    is_authenticated = True
    is_anonymous = False
    username = "api-token"

    def __str__(self) -> str:
        return self.username


class BearerTokenAuthentication(authentication.BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        expected = get_config().secrets.soc_api_token
        if not expected:
            return None
        header = authentication.get_authorization_header(request).decode("utf-8", "ignore")
        if not header:
            return None
        parts = header.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            raise exceptions.AuthenticationFailed("Invalid Authorization header. Use: Bearer <token>")
        if not hmac.compare_digest(parts[1], expected):
            raise exceptions.AuthenticationFailed("Invalid API token.")
        return TokenUser(), None

    def authenticate_header(self, request):
        return self.keyword


class TokenRequiredIfConfigured(permissions.BasePermission):
    """Open when no token is configured (local dev); otherwise require auth."""

    message = "Authentication required. Set Authorization: Bearer <SOC_API_TOKEN>."

    def has_permission(self, request, view):
        if getattr(view, "public", False):
            return True
        if not get_config().secrets.soc_api_token:
            return True
        return bool(request.user and getattr(request.user, "is_authenticated", False))


def auth_enabled() -> bool:
    return bool(get_config().secrets.soc_api_token)
