"""Combine IP, headers, and auth signals into one rate-limit key.

Priority order: authenticated identity (most accurate, survives IP
rotation and shared-NAT collisions) > anonymous IP + header
fingerprint fallback. This means a logged-in user keeps a stable
bucket across a train commute's worth of cell-tower handoffs, while an
anonymous scraper rotating IPs still gets *some* signal from its
header fingerprint even though it can't be pinned to one bucket.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence

from ..types import Fingerprint
from .auth import extract_identity
from .headers import header_fingerprint
from .ip import extract_client_ip, fingerprint_key


def build_fingerprint(
    headers: Mapping[str, str],
    direct_ip: str,
    trust_x_forwarded_for: bool = False,
    trusted_proxies: Optional[Sequence[str]] = None,
    api_key_header: str = "x-api-key",
) -> Fingerprint:
    ip = extract_client_ip(headers, direct_ip, trust_x_forwarded_for, trusted_proxies)
    normalized_ip = fingerprint_key(ip)
    identity = extract_identity(headers, api_key_header)
    ua_hash = header_fingerprint(headers)

    return Fingerprint(
        ip=normalized_ip,
        identity=identity,
        user_agent_hash=ua_hash,
        source="identity" if identity else "ip",
    )
