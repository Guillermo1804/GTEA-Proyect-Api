from __future__ import annotations

from typing import Optional, Tuple

from django.conf import settings
from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.request import Request
from rest_framework.response import Response


class CookieTokenAuthentication(TokenAuthentication):
    """DRF TokenAuthentication that also accepts the token from an HttpOnly cookie.

    Priority:
    1) Standard `Authorization: Token <key>` header (compatibility with Postman/curl)
    2) Cookie named by `AUTH_TOKEN_COOKIE_NAME` (default: `auth_token`)

    This is intended for local/dev use with SPAs where forgetting the Authorization
    header causes 401s.
    """

    def authenticate(self, request: Request) -> Optional[Tuple[object, object]]:
        auth_header = get_authorization_header(request)
        if auth_header:
            return super().authenticate(request)

        cookie_name = getattr(settings, 'AUTH_TOKEN_COOKIE_NAME', 'auth_token')
        token_key = request.COOKIES.get(cookie_name)
        if not token_key:
            return None

        # TokenAuthentication.authenticate_credentials expects a string key
        return self.authenticate_credentials(token_key)


def set_auth_token_cookie(response: Response, token_key: str) -> None:
    cookie_name = getattr(settings, 'AUTH_TOKEN_COOKIE_NAME', 'auth_token')
    secure = bool(getattr(settings, 'AUTH_TOKEN_COOKIE_SECURE', False))
    samesite = getattr(settings, 'AUTH_TOKEN_COOKIE_SAMESITE', 'Lax')
    max_age = getattr(settings, 'AUTH_TOKEN_COOKIE_MAX_AGE', None)

    response.set_cookie(
        cookie_name,
        token_key,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=max_age,
        path='/',
    )


def clear_auth_token_cookie(response: Response) -> None:
    cookie_name = getattr(settings, 'AUTH_TOKEN_COOKIE_NAME', 'auth_token')
    response.delete_cookie(cookie_name, path='/')
