"""
tests/test_dh.py

Unit tests for crypto/dh.py

Run with:
    python -m pytest tests/test_dh.py -v
"""

import pytest
from crypto.dh import DHKeyExchange, P, G, _hkdf_sha256


# ---------------------------------------------------------------------------
# DHKeyExchange tests
# ---------------------------------------------------------------------------

class TestDHKeyExchange:

    def test_public_key_in_valid_range(self):
        """Public key must be in [2, P-2]."""
        dh = DHKeyExchange()
        assert 2 <= dh.get_public_key() <= P - 2

    def test_two_parties_derive_same_session_key(self):
        """Core DH property: both sides must arrive at the same session key."""
        alice = DHKeyExchange()
        bob = DHKeyExchange()

        alice_key = alice.derive_session_key(bob.get_public_key())
        bob_key = bob.derive_session_key(alice.get_public_key())

        assert alice_key == bob_key

    def test_session_key_is_32_bytes(self):
        """Session key must be exactly 32 bytes (AES-256 requirement)."""
        alice = DHKeyExchange()
        bob = DHKeyExchange()
        key = alice.derive_session_key(bob.get_public_key())
        assert len(key) == 32

    def test_session_key_is_bytes(self):
        """Session key must be of type bytes."""
        alice = DHKeyExchange()
        bob = DHKeyExchange()
        key = alice.derive_session_key(bob.get_public_key())
        assert isinstance(key, bytes)

    def test_repeated_derive_returns_same_key(self):
        """Calling derive_session_key twice must return the same cached key."""
        alice = DHKeyExchange()
        bob = DHKeyExchange()
        key1 = alice.derive_session_key(bob.get_public_key())
        key2 = alice.derive_session_key(bob.get_public_key())
        assert key1 == key2

    def test_different_sessions_produce_different_keys(self):
        """Two independent sessions must produce different session keys."""
        alice1, bob1 = DHKeyExchange(), DHKeyExchange()
        alice2, bob2 = DHKeyExchange(), DHKeyExchange()
        key1 = alice1.derive_session_key(bob1.get_public_key())
        key2 = alice2.derive_session_key(bob2.get_public_key())
        assert key1 != key2

    def test_public_keys_differ_across_instances(self):
        """Each instance must generate a distinct public key."""
        keys = {DHKeyExchange().get_public_key() for _ in range(10)}
        assert len(keys) == 10

    def test_invalid_peer_key_too_small(self):
        """Peer public key of 1 must be rejected."""
        dh = DHKeyExchange()
        with pytest.raises(ValueError, match="out of valid range"):
            dh.derive_session_key(1)

    def test_invalid_peer_key_zero(self):
        """Peer public key of 0 must be rejected."""
        dh = DHKeyExchange()
        with pytest.raises(ValueError, match="out of valid range"):
            dh.derive_session_key(0)

    def test_invalid_peer_key_equals_p(self):
        """Peer public key equal to P must be rejected."""
        dh = DHKeyExchange()
        with pytest.raises(ValueError, match="out of valid range"):
            dh.derive_session_key(P)

    def test_invalid_peer_key_negative(self):
        """Negative peer public key must be rejected."""
        dh = DHKeyExchange()
        with pytest.raises(ValueError, match="out of valid range"):
            dh.derive_session_key(-1)

    def test_invalid_peer_key_wrong_type(self):
        """Non-integer peer public key must be rejected."""
        dh = DHKeyExchange()
        with pytest.raises(ValueError, match="must be an integer"):
            dh.derive_session_key("notanint")

    def test_small_subgroup_key_rejected(self):
        """
        A peer public key of P-1 has order 2 (small subgroup).
        Must be rejected by subgroup validation.
        """
        dh = DHKeyExchange()
        with pytest.raises(ValueError):
            dh.derive_session_key(P - 1)


# ---------------------------------------------------------------------------
# HKDF tests
# ---------------------------------------------------------------------------

class TestHKDF:

    def test_output_length_32(self):
        """HKDF must return exactly 32 bytes when length=32."""
        out = _hkdf_sha256(b"input", length=32)
        assert len(out) == 32

    def test_output_length_16(self):
        """HKDF must return exactly 16 bytes when length=16."""
        out = _hkdf_sha256(b"input", length=16)
        assert len(out) == 16

    def test_deterministic(self):
        """Same inputs must always produce the same output."""
        a = _hkdf_sha256(b"ikm", length=32, info=b"ctx", salt=b"salt")
        b = _hkdf_sha256(b"ikm", length=32, info=b"ctx", salt=b"salt")
        assert a == b

    def test_different_info_produces_different_output(self):
        """Different info strings must produce different keys (domain separation)."""
        a = _hkdf_sha256(b"ikm", length=32, info=b"context_a")
        b = _hkdf_sha256(b"ikm", length=32, info=b"context_b")
        assert a != b

    def test_different_ikm_produces_different_output(self):
        """Different input key material must produce different output."""
        a = _hkdf_sha256(b"ikm_one", length=32)
        b = _hkdf_sha256(b"ikm_two", length=32)
        assert a != b

    def test_output_is_bytes(self):
        """HKDF output must be of type bytes."""
        out = _hkdf_sha256(b"ikm", length=32)
        assert isinstance(out, bytes)

    def test_exceeding_max_length_raises(self):
        """Requesting more than 255*32 bytes must raise ValueError."""
        with pytest.raises(ValueError, match="exceeds maximum"):
            _hkdf_sha256(b"ikm", length=255 * 32 + 1)

    def test_known_vector(self):
        """
        RFC 5869 Test Case 1 — SHA-256, basic.
        Verifies our HKDF implementation against a published test vector.

        IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
        salt = 0x000102030405060708090a0b0c
        info = 0xf0f1f2f3f4f5f6f7f8f9
        L    = 42

        Expected OKM (first 32 bytes used here):
        3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
        (full 42-byte OKM truncated to 32 for this assertion)
        """
        ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected_first_32 = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        )
        out = _hkdf_sha256(ikm, length=32, info=info, salt=salt)
        assert out == expected_first_32