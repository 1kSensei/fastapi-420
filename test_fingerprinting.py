import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi_420.fingerprinting.auth import extract_identity, extract_jwt_subject
from fastapi_420.fingerprinting.composite import build_fingerprint
from fastapi_420.fingerprinting.ip import extract_client_ip, fingerprint_key, normalize_ip


def fake_jwt(payload: dict) -> str:
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none'})}.{b64(payload)}.fakesig"


class IPTests(unittest.TestCase):
    def test_normalize_strips_port(self):
        self.assertEqual(normalize_ip("1.2.3.4:8080"), "1.2.3.4")

    def test_normalize_strips_bracketed_ipv6_port(self):
        self.assertEqual(normalize_ip("[2001:db8::1]:443"), "2001:db8::1")

    def test_ipv6_collapses_to_slash_64(self):
        a = fingerprint_key("2001:db8:1234:5678:aaaa:bbbb:cccc:1111")
        b = fingerprint_key("2001:db8:1234:5678:ffff:ffff:ffff:ffff")
        self.assertEqual(a, b)
        self.assertEqual(a, "2001:db8:1234:5678::")

    def test_ipv4_untouched(self):
        self.assertEqual(fingerprint_key("203.0.113.7"), "203.0.113.7")

    def test_untrusted_xff_is_ignored_by_default(self):
        ip = extract_client_ip(
            {"x-forwarded-for": "6.6.6.6"}, direct_ip="9.9.9.9", trust_x_forwarded_for=False
        )
        self.assertEqual(ip, "9.9.9.9")

    def test_xff_walks_past_trusted_proxies(self):
        ip = extract_client_ip(
            headers={"x-forwarded-for": "203.0.113.7, 10.0.0.5"},
            direct_ip="10.0.0.5",  # our load balancer
            trust_x_forwarded_for=True,
            trusted_proxies=["10.0.0.5"],
        )
        self.assertEqual(ip, "203.0.113.7")


class AuthTests(unittest.TestCase):
    def test_extract_jwt_subject(self):
        token = fake_jwt({"sub": "user-42"})
        self.assertEqual(extract_jwt_subject(token), "user-42")

    def test_malformed_jwt_returns_none(self):
        self.assertIsNone(extract_jwt_subject("not-a-jwt"))

    def test_priority_bearer_over_api_key(self):
        headers = {
            "authorization": f"Bearer {fake_jwt({'sub': 'abc'})}",
            "x-api-key": "should-not-be-used",
        }
        self.assertEqual(extract_identity(headers), "user:abc")

    def test_api_key_fallback(self):
        headers = {"x-api-key": "sk_live_1234567890abcdef"}
        identity = extract_identity(headers)
        self.assertTrue(identity.startswith("key:"))
        self.assertNotIn("1234567890abcdef", identity)  # truncated, not the raw key

    def test_no_credentials_returns_none(self):
        self.assertIsNone(extract_identity({}))


class CompositeFingerprintTests(unittest.TestCase):
    def test_authenticated_user_uses_identity_source(self):
        fp = build_fingerprint(
            headers={"authorization": f"Bearer {fake_jwt({'sub': 'u1'})}"},
            direct_ip="1.2.3.4",
        )
        self.assertEqual(fp.source, "identity")
        self.assertEqual(fp.key(), "identity:user:u1")

    def test_anonymous_client_falls_back_to_ip(self):
        fp = build_fingerprint(headers={}, direct_ip="1.2.3.4")
        self.assertEqual(fp.source, "ip")
        self.assertEqual(fp.key(), "ip:1.2.3.4")


if __name__ == "__main__":
    unittest.main()
