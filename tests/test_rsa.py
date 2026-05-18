"""
tests/test_rsa.py

Unit tests for crypto/rsa.py

Note: RSA key generation at 2048 bits takes a few seconds.
The keypair fixture is session-scoped so it's generated once for all tests.

Run with:
    python -m pytest tests/test_rsa.py -v
"""

import pytest
import secrets
from crypto.rsa import (
    generate_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    _miller_rabin,
    _mod_inverse,
    _gcd,
    RSAPublicKey,
    RSAPrivateKey,
)


# ---------------------------------------------------------------------------
# Session-scoped keypair — generated once, reused across all tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def keypair():
    return generate_keypair(bits=2048)


@pytest.fixture(scope="session")
def pub(keypair):
    return keypair[0]


@pytest.fixture(scope="session")
def priv(keypair):
    return keypair[1]


# ---------------------------------------------------------------------------
# Miller-Rabin tests
# ---------------------------------------------------------------------------

class TestMillerRabin:

    def test_known_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 101, 7919, 104729]:
            assert _miller_rabin(p), f"{p} should be prime"

    def test_known_composites(self):
        for n in [4, 6, 8, 9, 15, 100, 561, 1105]:  # 561, 1105 are Carmichael numbers
            assert not _miller_rabin(n), f"{n} should be composite"

    def test_one_is_not_prime(self):
        assert not _miller_rabin(1)

    def test_zero_is_not_prime(self):
        assert not _miller_rabin(0)

    def test_large_prime(self):
        # A known large prime
        p = 2**127 - 1  # Mersenne prime M127
        assert _miller_rabin(p)

    def test_large_composite(self):
        # Product of two primes — definitely composite
        assert not _miller_rabin(104729 * 15485863)


# ---------------------------------------------------------------------------
# Modular arithmetic tests
# ---------------------------------------------------------------------------

class TestModArithmetic:

    def test_mod_inverse_basic(self):
        assert _mod_inverse(3, 7) == 5  # 3*5 = 15 ≡ 1 (mod 7)

    def test_mod_inverse_times_original_is_one(self):
        a, m = 17, 3120
        inv = _mod_inverse(a, m)
        assert (a * inv) % m == 1

    def test_mod_inverse_no_inverse_raises(self):
        with pytest.raises(ValueError):
            _mod_inverse(4, 8)  # gcd(4,8) = 4, no inverse

    def test_gcd_basic(self):
        assert _gcd(12, 8) == 4
        assert _gcd(7, 13) == 1
        assert _gcd(100, 75) == 25


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------

class TestKeyGeneration:

    def test_keypair_types(self, pub, priv):
        assert isinstance(pub, RSAPublicKey)
        assert isinstance(priv, RSAPrivateKey)

    def test_modulus_bit_length(self, pub):
        assert pub.n.bit_length() == 2048

    def test_public_exponent_is_65537(self, pub):
        assert pub.e == 65537

    def test_modulus_matches(self, pub, priv):
        assert pub.n == priv.n

    def test_primes_are_distinct(self, priv):
        assert priv.p != priv.q

    def test_key_equation_holds(self, pub, priv):
        """e * d ≡ 1 (mod (p-1)(q-1))"""
        phi_n = (priv.p - 1) * (priv.q - 1)
        assert (pub.e * priv.d) % phi_n == 1

    def test_invalid_bits_raises(self):
        with pytest.raises(ValueError):
            generate_keypair(bits=511)

    def test_odd_bits_raises(self):
        with pytest.raises(ValueError):
            generate_keypair(bits=513)


# ---------------------------------------------------------------------------
# RSA encrypt / decrypt tests
# ---------------------------------------------------------------------------

class TestRSAEncryptDecrypt:

    def test_roundtrip(self, pub, priv):
        msg = b"challenge_token_abc123"
        assert rsa_decrypt(rsa_encrypt(msg, pub), priv) == msg

    def test_roundtrip_single_byte(self, pub, priv):
        assert rsa_decrypt(rsa_encrypt(b"\x42", pub), priv) == b"\x42"

    def test_ciphertext_is_bytes(self, pub):
        ct = rsa_encrypt(b"hello", pub)
        assert isinstance(ct, bytes)

    def test_ciphertext_length_equals_key_size(self, pub):
        ct = rsa_encrypt(b"hello", pub)
        assert len(ct) == 256  # 2048 bits = 256 bytes

    def test_different_encryptions_differ(self, pub):
        """PKCS#1 v1.5 uses random padding — same message encrypts differently."""
        msg = b"same_message"
        ct1 = rsa_encrypt(msg, pub)
        ct2 = rsa_encrypt(msg, pub)
        assert ct1 != ct2

    def test_message_too_long_raises(self, pub):
        """Max message length for RSA-2048 PKCS#1 v1.5 is 245 bytes."""
        with pytest.raises(ValueError, match="too long"):
            rsa_encrypt(b"A" * 246, pub)

    def test_max_length_message(self, pub, priv):
        """245-byte message must encrypt and decrypt correctly."""
        msg = b"B" * 245
        assert rsa_decrypt(rsa_encrypt(msg, pub), priv) == msg

    def test_wrong_key_decrypt_raises_or_corrupts(self, pub, priv):
        """Decrypting with a mismatched key must not silently return original."""
        msg = b"secret_challenge"
        ct = rsa_encrypt(msg, pub)
        pub2, priv2 = generate_keypair(bits=2048)
        try:
            result = rsa_decrypt(ct, priv2)
            assert result != msg
        except (ValueError, OverflowError):
            pass


# ---------------------------------------------------------------------------
# RSA sign / verify tests
# ---------------------------------------------------------------------------

class TestRSASignVerify:

    def test_valid_signature_verifies(self, pub, priv):
        msg = b"vote accepted: candidate_1"
        sig = rsa_sign(msg, priv)
        assert rsa_verify(msg, sig, pub) is True

    def test_signature_is_bytes(self, pub, priv):
        sig = rsa_sign(b"message", priv)
        assert isinstance(sig, bytes)

    def test_signature_length_equals_key_size(self, pub, priv):
        sig = rsa_sign(b"message", priv)
        assert len(sig) == 256

    def test_tampered_message_fails(self, pub, priv):
        msg = b"vote accepted: candidate_1"
        sig = rsa_sign(msg, priv)
        assert rsa_verify(b"vote accepted: candidate_2", sig, pub) is False

    def test_tampered_signature_fails(self, pub, priv):
        msg = b"vote accepted: candidate_1"
        sig = bytearray(rsa_sign(msg, priv))
        sig[10] ^= 0xFF  # Flip bits in signature
        assert rsa_verify(msg, bytes(sig), pub) is False

    def test_wrong_key_verify_fails(self, pub, priv):
        msg = b"vote accepted: candidate_1"
        sig = rsa_sign(msg, priv)
        pub2, _ = generate_keypair(bits=2048)
        assert rsa_verify(msg, sig, pub2) is False

    def test_empty_message(self, pub, priv):
        msg = b""
        sig = rsa_sign(msg, priv)
        assert rsa_verify(msg, sig, pub) is True

    def test_long_message(self, pub, priv):
        """Signature covers SHA-256 hash, so message length is unbounded."""
        msg = b"x" * 10000
        sig = rsa_sign(msg, priv)
        assert rsa_verify(msg, sig, pub) is True

    def test_signature_deterministic(self, pub, priv):
        """PKCS#1 v1.5 signing is deterministic — same message, same signature."""
        msg = b"deterministic_test"
        assert rsa_sign(msg, priv) == rsa_sign(msg, priv)

    def test_verify_returns_false_not_raises_on_bad_input(self, pub):
        """rsa_verify must never raise — bad input returns False."""
        assert rsa_verify(b"msg", b"\x00" * 256, pub) is False