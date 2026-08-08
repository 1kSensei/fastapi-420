"""Client IP extraction and normalization.

Two separate concerns:

1. Figuring out the real client IP when requests pass through
   proxies/load balancers (X-Forwarded-For), without blindly trusting
   a header any client can set to whatever it wants.
2. Normalizing IPv6 addresses to their /64 block. Residential and
   mobile ISPs routinely hand a single customer a full /64 (some hand
   out even more), and many OSes rotate the host portion of their
   address (privacy extensions, RFC 4941) on their own — a client can
   cycle through ~2^64 distinct addresses without doing anything an
   attacker would recognize as "evasion". Limiting the /64 instead of
   the full 128-bit address closes that bypass.
"""
from __future__ import annotations

import ipaddress
from typing import Mapping, Optional, Sequence


def normalize_ip(raw: str) -> str:
    """Validate and canonicalize an IP string, stripping any port suffix."""
    raw = raw.strip()
    if raw.startswith("[") and "]" in raw:  # "[::1]:1234"
        raw = raw[1 : raw.index("]")]
    elif raw.count(":") == 1:  # "1.2.3.4:1234" (a bare IPv6 addr has >1 colon)
        raw = raw.split(":")[0]
    return str(ipaddress.ip_address(raw))


def extract_client_ip(
    headers: Mapping[str, str],
    direct_ip: str,
    trust_x_forwarded_for: bool = False,
    trusted_proxies: Optional[Sequence[str]] = None,
) -> str:
    """Return the best-guess real client IP.

    With `trust_x_forwarded_for=False` (the safe default), the socket
    peer address is authoritative — headers are attacker-controlled
    input and ignored entirely.

    With it enabled, walk the X-Forwarded-For chain from the right
    (closest to us, added by the proxy hop nearest our server) and
    return the first hop that ISN'T one of our own `trusted_proxies` —
    that's either the real client, or the first hop an attacker
    controls, which is the strongest guarantee any XFF-based scheme
    can make (a client can always lie about *earlier* hops it added
    itself before reaching our trusted proxy).
    """
    if not trust_x_forwarded_for:
        return normalize_ip(direct_ip)

    xff = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if not xff:
        return normalize_ip(direct_ip)

    trusted = {normalize_ip(p) for p in (trusted_proxies or [])}
    trusted.add(normalize_ip(direct_ip))

    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            candidate = normalize_ip(hop)
        except ValueError:
            continue
        if candidate not in trusted:
            return candidate

    return normalize_ip(direct_ip)  # every hop was "trusted"; fall back


def fingerprint_key(ip: str) -> str:
    """Collapse an IPv6 address to its /64 network address; IPv4 is untouched."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address):
        network = ipaddress.ip_network(f"{ip}/64", strict=False)
        return str(network.network_address)
    return str(addr)
