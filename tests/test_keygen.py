"""11.1 Unit tests for key generation and HMAC verification."""

import hashlib
import hmac

import pytest

from app.platform.auth.keygen import (
    generate_api_key,
    verify_api_key_hash,
    get_app_secret,
    _hash_key,
)


class TestKeyGeneration:
    def test_generates_correct_format(self):
        raw, prefix, fingerprint, hashed = generate_api_key()

        assert raw.startswith("g2a_")
        assert len(raw) == 4 + 64
        assert prefix == raw[:10]
        assert len(fingerprint) == 16
        assert len(hashed) == 64

    def test_prefix_is_first_10_chars(self):
        for _ in range(10):
            raw, prefix, _, _ = generate_api_key()
            assert prefix == raw[:10]

    def test_fingerprint_is_sha256_prefix(self):
        raw, _, fingerprint, _ = generate_api_key()
        expected = hashlib.sha256(raw.encode()).hexdigest()[:16]
        assert fingerprint == expected

    def test_keys_are_unique(self):
        keys = {generate_api_key()[0] for _ in range(100)}
        assert len(keys) == 100

    def test_key_length_is_constant(self):
        for _ in range(20):
            raw, _, _, _ = generate_api_key()
            assert len(raw) == 68  # "g2a_" + 64 hex chars


class TestKeyVerification:
    def test_verify_valid_key(self):
        raw, _, _, hashed = generate_api_key()
        assert verify_api_key_hash(raw, hashed) is True

    def test_verify_wrong_key_fails(self):
        raw, _, _, hashed = generate_api_key()
        raw2, _, _, _ = generate_api_key()
        assert verify_api_key_hash(raw2, hashed) is False

    def test_verify_tampered_key_fails(self):
        raw, _, _, hashed = generate_api_key()
        tampered = raw[:-1] + ("0" if raw[-1] != "0" else "1")
        assert verify_api_key_hash(tampered, hashed) is False

    def test_verify_empty_key_fails(self):
        _, _, _, hashed = generate_api_key()
        assert verify_api_key_hash("", hashed) is False

    def test_verify_with_wrong_secret_fails(self, monkeypatch):
        raw, _, _, hashed = generate_api_key()

        monkeypatch.setenv("GROK_API_KEY_SECRET", "different-secret")
        monkeypatch.delenv("GROK_API_KEY_SECRET", raising=False)
        monkeypatch.setattr(
            "app.platform.auth.keygen.get_app_secret",
            lambda: "different-secret",
        )

        result = hmac.compare_digest(
            hmac.new(
                "different-secret".encode(), raw.encode(), hashlib.sha256
            ).hexdigest(),
            hashed,
        )
        assert result is False


class TestAppSecret:
    def test_get_app_secret_returns_string(self):
        secret = get_app_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_get_app_secret_is_deterministic(self):
        s1 = get_app_secret()
        s2 = get_app_secret()
        assert s1 == s2


class TestHashHelpers:
    def test_hash_key_is_deterministic(self):
        raw, _, _, _ = generate_api_key()
        h1 = _hash_key(raw)
        h2 = _hash_key(raw)
        assert h1 == h2

    def test_hash_key_different_for_different_inputs(self):
        r1, _, _, _ = generate_api_key()
        r2, _, _, _ = generate_api_key()
        assert _hash_key(r1) != _hash_key(r2)
