"""
Centralised API error handling.

Every error leaves the API in one shape::

    {"error": {"code": "validation_error", "message": "...", "details": {...}}}

Unexpected exceptions are logged with a stack trace but the client only sees a
generic message (no internal details leak to the browser).
"""
from __future__ import annotations

import logging

from django.http import Http404
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_default_handler

logger = logging.getLogger("soc.api")


class ServiceUnavailable(exceptions.APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "A required service is unavailable."
    default_code = "service_unavailable"


def error_response(code: str, message: str, http_status: int, details=None) -> Response:
    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return Response(body, status=http_status)


def api_exception_handler(exc, context):
    response = drf_default_handler(exc, context)
    if response is not None:
        if isinstance(exc, exceptions.ValidationError):
            return error_response("validation_error", "Request validation failed.", response.status_code,
                                  response.data)
        if isinstance(exc, Http404):
            return error_response("not_found", "Resource not found.", status.HTTP_404_NOT_FOUND)
        code = getattr(exc, "default_code", "error")
        detail = response.data.get("detail", str(exc)) if isinstance(response.data, dict) else str(exc)
        resp = error_response(str(code), str(detail), response.status_code)
        for header in ("Retry-After", "WWW-Authenticate"):
            if header in response:
                resp[header] = response[header]
        return resp

    view = context.get("view")
    logger.exception("Unhandled API error", extra={"view": view.__class__.__name__ if view else "?"})
    return error_response("internal_error", "An unexpected error occurred. Check the backend logs.",
                          status.HTTP_500_INTERNAL_SERVER_ERROR)
