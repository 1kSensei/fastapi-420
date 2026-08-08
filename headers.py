"""Header-based signals for fingerprinting anonymous clients.

Supplementary, never primary: User-Agent and Accept-* headers cost an
attacker nothing to spoof. They're useful for (a) adding entropy when
many real users share one IP (CGNAT, corporate NAT, a campus network)
so they don't all fight over one bucket, and (b) flagging obviously
scripted traffic for extra scrutiny — never as a standalone identity
or a trust boundary.
"""
from __future__ import annotations

import hashlib
from typing import Mapping

_SUSPICIOUS_UA_SUBSTRINGS = ("curl", "python-requests", "go-http-client", "scrapy", "wget")


def header_fingerprint(headers: Mapping[str, str]) -> str:
    ua = headers.get("user-agent", headers.get("User-Agent", ""))
    accept = headers.get("accept", headers.get("Accept", ""))
    accept_lang = headers.get("accept-language", headers.get("Accept-Language", ""))
    raw = f"{ua}|{accept}|{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def looks_automated(headers: Mapping[str, str]) -> bool:
    """Heuristic only — used for logging/metrics, never to block outright."""
    ua = headers.get("user-agent", headers.get("User-Agent", "")).lower()
    if not ua:
        return True  # real browsers always send one
    return any(sub in ua for sub in _SUSPICIOUS_UA_SUBSTRINGS)
