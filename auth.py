"""Extract an authenticated identity from a request, when one exists.

For JWTs we only *decode* the payload to read a claim (sub/user_id/uid)
— we deliberately never verify the signature here, and this module has
no opinion on which algorithm signed the token. Rate limiting by
claimed identity is a usability optimization (give an authenticated
user their own bucket instead of making them share their IP's with
every other client on that NAT), not an authentication boundary; the
application's real auth middleware is what actually trusts the token.
An attacker who forges a JWT to steal a rate-limit bucket has gained
nothing but a shared quota with whichever `sub` they picked.
"""
from __future__ import annotations

import base64
import json
from typing import Mapping, Optional


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def extract_jwt_subject(token: str) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError):
        return None
    subject = payload.get("sub") or payload.get("user_id") or payload.get("uid")
    return str(subject) if subject is not None else None


def extract_identity(headers: Mapping[str, str], api_key_header: str = "x-api-key") -> Optional[str]:
    """Best-effort identity extraction, checked in priority order:
    Bearer JWT > API key header > session cookie > None (anonymous).
    """
    auth = headers.get("authorization") or headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        subject = extract_jwt_subject(auth[7:].strip())
        if subject:
            return f"user:{subject}"

    api_key = headers.get(api_key_header.lower()) or headers.get(api_key_header)
    if api_key:
        return f"key:{api_key[:12]}"  # truncated: the raw key never becomes a stored/logged value

    cookie_header = headers.get("cookie", headers.get("Cookie", ""))
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, _, value = part.strip().partition("=")
        if name == "session_id" and value:
            return f"session:{value[:16]}"

    return None
