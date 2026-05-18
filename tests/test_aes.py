"""
tests/test_aes.py

Unit tests for crypto/aes.py

Includes NIST FIPS 197 Appendix B known-answer test vectors.

Run with:
    python -m pytest tests/test_aes.py -v
"""

import pytest
from crypto.aes import (
    aes_encrypt,
    aes_decrypt,
    _pkcs7_pad,
    _pkcs7_unpad,
    _aes_encrypt_block,
    _aes_decrypt_block,
    _key_expansion,
    _gmul,
)


# ---------------------------------------------------------------------------
# GF(2^8) multiplication tests
# ---------------------------------------------------------------------------

class TestGmul:

    def test_multiply_by_one_is_identity(self):
        """Multiplying any value by 1 in GF(2^8) must return the value."""
        for v in [0x00, 0x53, 0xFF, 0xAB]:
            assert _gmul(v, 0x01) == v

    def test_multiply_by_zero(self):
        """Multiplying any value by 0 must return 0."""
        for v in [0x00, 0x53, 0xFF]:
            assert _gmul(v, 0x00) == 0

    def test_known_values(self):
        """
        FIPS 197 Section 4.2 example:
        {57} * {83} = {c1} in GF(2^8)
        """
        assert _gmul(0x57, 0x83) == 0xC1

    def test_commutativity(self):
        """GF multiplication must be commutative."""
        assert _gmul(0x57, 0x13) == _gmul(0x13, 0x57)


# ---------------------------------------------------------------------------
# PKCS7 padding tests
# ---------------------------------------------------------------------------

class TestPKCS7:

    def test_pad_adds_full_block_when_aligned(self):
        """If input is already block-aligned, a full padding block must be added."""
        data = b"A" * 16
        padded = _pkcs7_pad(data)
        assert len(padded) == 32
        assert padded[16:] == bytes([16] * 16)

    def test_pad_short_input(self):
        """3-byte input needs 13 bytes of padding to reach 16."""
        padded = _pkcs7_pad(b"abc")
        assert len(padded) == 16
        assert padded[3:] == bytes([13] * 13)

    def test_unpad_reverses_pad(self):
        """Unpadding a padded value must return the original."""
        original = b"hello world"
        assert _pkcs7_unpad(_pkcs7_pad(original)) == original

    def test_unpad_aligned_input(self):
        """Unpadding a full block of padding must return empty bytes."""
        assert _pkcs7_unpad(bytes([16] * 16)) == b""

    def test_unpad_invalid_zero_byte(self):
        """Padding byte of 0x00 is invalid."""
        with pytest.raises(ValueError, match="Invalid PKCS7 padding byte"):
            _pkcs7_unpad(b"A" * 15 + b"\x00")

    def test_unpad_invalid_inconsistent(self):
        """Padding bytes that don't all match must raise ValueError."""
        with pytest.raises(ValueError, match="inconsistent"):
            _pkcs7_unpad(b"A" * 14 + b"\x02\x03")

    def test_unpad_empty_raises(self):
        """Empty input must raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            _pkcs7_unpad(b"")


# ---------------------------------------------------------------------------
# NIST FIPS 197 Appendix B — known-answer test (AES-128 block)
#
# Note: FIPS 197 Appendix B uses a 128-bit key for its worked example.
# We test the block cipher internals with this vector to verify correctness
# of SubBytes, ShiftRows, MixColumns, and AddRoundKey implementations.
# The AES-256 key schedule is separately verified via encrypt/decrypt
# round-trip tests with 256-bit keys below.
# ---------------------------------------------------------------------------

class TestAESBlockFIPS197:

    def test_fips197_appendix_b_encrypt(self):
        """
        FIPS 197 Appendix B:
        Plaintext:  3243F6A8885A308D313198A2E0370734
        Key:        2B7E151628AED2A6ABF7158809CF4F3C
        Ciphertext: 3925841D02DC09FBDC118597196A0B32
        """
        # We verify using our _aes_encrypt_block with AES-128 round keys.
        # Since our implementation targets AES-256, we replicate the AES-128
        # key schedule here for this specific test vector only.
        plaintext = bytes.fromhex("3243F6A8885A308D313198A2E0370734")
        key_128   = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        expected  = bytes.fromhex("3925841D02DC09FBDC118597196A0B32")

        # AES-128 key expansion (Nk=4, Nr=10)
        round_keys = _key_expansion_128(key_128)
        result = _aes_encrypt_block_nr(plaintext, round_keys, nr=10)
        assert result == expected

    def test_fips197_appendix_b_decrypt(self):
        """
        Reverse of the FIPS 197 Appendix B vector.
        """
        ciphertext = bytes.fromhex("3925841D02DC09FBDC118597196A0B32")
        key_128    = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        expected   = bytes.fromhex("3243F6A8885A308D313198A2E0370734")

        round_keys = _key_expansion_128(key_128)
        result = _aes_decrypt_block_nr(ciphertext, round_keys, nr=10)
        assert result == expected


# ---------------------------------------------------------------------------
# AES-256 known-answer test (NIST AES-256-ECB vector)
# ---------------------------------------------------------------------------

class TestAES256KnownVector:

    def test_nist_aes256_ecb_vector(self):
        """
        NIST CAVS AES-256 ECB Known Answer Test:
        Key:        000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
        Plaintext:  00112233445566778899AABBCCDDEEFF
        Ciphertext: 8EA2B7CA516745BFEAFC49904B496089
        """
        key       = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        expected  = bytes.fromhex("8EA2B7CA516745BFEAFC49904B496089")

        round_keys = _key_expansion(key)
        result = _aes_encrypt_block(plaintext, round_keys)
        assert result == expected

    def test_nist_aes256_ecb_vector_decrypt(self):
        """Inverse of the NIST AES-256 ECB vector."""
        key        = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        ciphertext = bytes.fromhex("8EA2B7CA516745BFEAFC49904B496089")
        expected   = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

        round_keys = _key_expansion(key)
        result = _aes_decrypt_block(ciphertext, round_keys)
        assert result == expected


# ---------------------------------------------------------------------------
# AES-256-CBC public API tests
# ---------------------------------------------------------------------------

class TestAESCBC:

    def setup_method(self):
        self.key = bytes(range(32))  # 32-byte key: 0x00..0x1F

    def test_encrypt_returns_bytes(self):
        ct = aes_encrypt(b"hello", self.key)
        assert isinstance(ct, bytes)

    def test_encrypt_prepends_iv(self):
        """Output must be at least 32 bytes: 16 IV + 16 ciphertext block."""
        ct = aes_encrypt(b"hello", self.key)
        assert len(ct) >= 32

    def test_encrypt_output_multiple_of_16_plus_iv(self):
        """Total output length must be a multiple of 16."""
        ct = aes_encrypt(b"vote:candidate_1", self.key)
        assert len(ct) % 16 == 0

    def test_roundtrip_short(self):
        """Encrypt then decrypt must return the original plaintext."""
        pt = b"vote:candidate_1"
        assert aes_decrypt(aes_encrypt(pt, self.key), self.key) == pt

    def test_roundtrip_empty(self):
        """Empty plaintext must round-trip correctly (becomes one padding block)."""
        pt = b""
        assert aes_decrypt(aes_encrypt(pt, self.key), self.key) == pt

    def test_roundtrip_exact_block(self):
        """Exactly 16 bytes — triggers a full padding block appended."""
        pt = b"A" * 16
        assert aes_decrypt(aes_encrypt(pt, self.key), self.key) == pt

    def test_roundtrip_long(self):
        """Multi-block plaintext must round-trip correctly."""
        pt = b"x" * 200
        assert aes_decrypt(aes_encrypt(pt, self.key), self.key) == pt

    def test_different_ivs_produce_different_ciphertext(self):
        """Two encryptions of the same plaintext must produce different output."""
        pt = b"vote:candidate_1"
        ct1 = aes_encrypt(pt, self.key)
        ct2 = aes_encrypt(pt, self.key)
        assert ct1 != ct2

    def test_wrong_key_fails_or_corrupts(self):
        """Decrypting with a different key must not return the original plaintext."""
        pt = b"vote:candidate_1"
        ct = aes_encrypt(pt, self.key)
        wrong_key = bytes([0xFF] * 32)
        try:
            result = aes_decrypt(ct, wrong_key)
            assert result != pt
        except ValueError:
            pass  # Invalid padding is also an acceptable outcome

    def test_wrong_key_length_encrypt_raises(self):
        with pytest.raises(ValueError, match="32-byte"):
            aes_encrypt(b"data", b"shortkey")

    def test_wrong_key_length_decrypt_raises(self):
        with pytest.raises(ValueError, match="32-byte"):
            aes_decrypt(b"\x00" * 32, b"shortkey")

    def test_ciphertext_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            aes_decrypt(b"\x00" * 16, self.key)

    def test_ciphertext_not_multiple_of_16_raises(self):
        with pytest.raises(ValueError, match="multiple of 16"):
            aes_decrypt(b"\x00" * 33, self.key)

    def test_roundtrip_unicode_encoded(self):
        """UTF-8 encoded text must round-trip correctly."""
        pt = "नमस्ते".encode("utf-8")
        assert aes_decrypt(aes_encrypt(pt, self.key), self.key) == pt


# ---------------------------------------------------------------------------
# Helper: AES-128 key expansion + block cipher for FIPS 197 test vector
# These are used only in TestAESBlockFIPS197 and are not part of the system.
# ---------------------------------------------------------------------------

from crypto.aes import _SBOX, _RCON, _bytes_to_state, _state_to_bytes
from crypto.aes import _add_round_key, _sub_bytes, _inv_sub_bytes
from crypto.aes import _shift_rows, _inv_shift_rows
from crypto.aes import _mix_columns, _inv_mix_columns


def _key_expansion_128(key: bytes) -> list[list[int]]:
    """AES-128 key expansion (Nk=4, Nr=10). For test vector use only."""
    assert len(key) == 16
    Nk, Nr = 4, 10
    w = [list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1][:]
        if i % Nk == 0:
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= _RCON[i // Nk]
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    return [[b for word in w[4*i:4*i+4] for b in word] for i in range(Nr+1)]


def _aes_encrypt_block_nr(block: bytes, round_keys, nr: int) -> bytes:
    """AES block encrypt with variable Nr. For test vector use only."""
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for r in range(1, nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[nr])
    return _state_to_bytes(state)


def _aes_decrypt_block_nr(block: bytes, round_keys, nr: int) -> bytes:
    """AES block decrypt with variable Nr. For test vector use only."""
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[nr])
    for r in range(nr-1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)