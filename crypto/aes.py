"""
crypto/aes.py

AES-256-CBC implemented from scratch.

No external crypto libraries used. Core AES operations (SubBytes, ShiftRows,
MixColumns, AddRoundKey, KeyExpansion) are implemented directly from the
NIST FIPS 197 specification.

Usage:
    from crypto.aes import aes_encrypt, aes_decrypt

    key        = bytes(32)               # 32-byte key from DH session
    plaintext  = b"vote:candidate_1"
    ciphertext = aes_encrypt(plaintext, key)   # IV prepended automatically
    recovered  = aes_decrypt(ciphertext, key)  # IV stripped automatically
"""

import os
import secrets


# ---------------------------------------------------------------------------
# AES S-Box and Inverse S-Box (FIPS 197, Figure 7)
# ---------------------------------------------------------------------------

_SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic — reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
# ---------------------------------------------------------------------------

def _xtime(a: int) -> int:
    """Multiply by x (i.e. 0x02) in GF(2^8)."""
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) using peasant's algorithm."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


# ---------------------------------------------------------------------------
# Round constants (FIPS 197, Section 5.2)
# ---------------------------------------------------------------------------

_RCON = [0x00] + [0] * 10
_RCON[1] = 0x01
for _i in range(2, 11):
    _RCON[_i] = _xtime(_RCON[_i - 1])


# ---------------------------------------------------------------------------
# Key Expansion — AES-256 produces 15 round keys (Nr+1 = 14+1)
# ---------------------------------------------------------------------------

def _key_expansion(key: bytes) -> list[list[int]]:
    """
    Expand a 32-byte AES-256 key into 15 round keys.
    Each round key is a 4x4 matrix (list of 4 rows, each 4 bytes).

    Args:
        key: 32-byte key.

    Returns:
        List of 15 round keys, each a flat list of 16 bytes.
    """
    assert len(key) == 32, "AES-256 requires a 32-byte key."

    Nk = 8   # key length in 32-bit words
    Nr = 14  # number of rounds for AES-256
    w = []

    # Initial key schedule from the raw key bytes
    for i in range(Nk):
        w.append(list(key[4*i : 4*i+4]))

    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            # RotWord + SubWord + Rcon
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= _RCON[i // Nk]
        elif i % Nk == 4:
            # SubWord only (AES-256 specific)
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    # Group words into round keys (each round key = 4 words = 16 bytes)
    round_keys = []
    for i in range(Nr + 1):
        rk = []
        for j in range(4):
            rk.extend(w[4*i + j])
        round_keys.append(rk)
    return round_keys


# ---------------------------------------------------------------------------
# State helpers — AES operates on a 4x4 byte matrix (the "state")
# ---------------------------------------------------------------------------

def _bytes_to_state(block: bytes) -> list[list[int]]:
    """Convert 16 bytes to a 4x4 state matrix (column-major per FIPS 197)."""
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    """Convert a 4x4 state matrix back to 16 bytes."""
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _add_round_key(state: list[list[int]], round_key: list[int]) -> list[list[int]]:
    """XOR state with round key."""
    return [[state[r][c] ^ round_key[r + 4*c] for c in range(4)] for r in range(4)]


def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """Apply S-Box substitution to every byte in the state."""
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """Apply inverse S-Box substitution to every byte in the state."""
    return [[_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Cyclically shift row i left by i positions."""
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Cyclically shift row i right by i positions."""
    return [
        [state[r][(c - r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    """Mix each column using GF(2^8) matrix multiplication."""
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(0x02,s[0])^_gmul(0x03,s[1])^s[2]^s[3]
        new_state[1][c] = s[0]^_gmul(0x02,s[1])^_gmul(0x03,s[2])^s[3]
        new_state[2][c] = s[0]^s[1]^_gmul(0x02,s[2])^_gmul(0x03,s[3])
        new_state[3][c] = _gmul(0x03,s[0])^s[1]^s[2]^_gmul(0x02,s[3])
    return new_state


def _inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """Inverse MixColumns using GF(2^8) matrix multiplication."""
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(0x0E,s[0])^_gmul(0x0B,s[1])^_gmul(0x0D,s[2])^_gmul(0x09,s[3])
        new_state[1][c] = _gmul(0x09,s[0])^_gmul(0x0E,s[1])^_gmul(0x0B,s[2])^_gmul(0x0D,s[3])
        new_state[2][c] = _gmul(0x0D,s[0])^_gmul(0x09,s[1])^_gmul(0x0E,s[2])^_gmul(0x0B,s[3])
        new_state[3][c] = _gmul(0x0B,s[0])^_gmul(0x0D,s[1])^_gmul(0x09,s[2])^_gmul(0x0E,s[3])
    return new_state


# ---------------------------------------------------------------------------
# AES-256 block cipher — single block encrypt / decrypt
# ---------------------------------------------------------------------------

def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """
    Encrypt a single 16-byte block with AES-256.

    Args:
        block: Exactly 16 bytes of plaintext.
        round_keys: 15 round keys from _key_expansion().

    Returns:
        16-byte ciphertext block.
    """
    assert len(block) == 16
    Nr = 14

    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])

    for rnd in range(1, Nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])

    # Final round — no MixColumns
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[Nr])

    return _state_to_bytes(state)


def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """
    Decrypt a single 16-byte block with AES-256.

    Args:
        block: Exactly 16 bytes of ciphertext.
        round_keys: 15 round keys from _key_expansion().

    Returns:
        16-byte plaintext block.
    """
    assert len(block) == 16
    Nr = 14

    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[Nr])

    for rnd in range(Nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)

    # Final round
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# ---------------------------------------------------------------------------
# PKCS7 padding
# ---------------------------------------------------------------------------

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Pad data to a multiple of block_size using PKCS7."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS7 padding.

    Raises:
        ValueError: If padding is invalid.
    """
    if not data:
        raise ValueError("Cannot unpad empty data.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS7 padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding: padding bytes inconsistent.")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Public API — AES-256-CBC encrypt / decrypt
# ---------------------------------------------------------------------------

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-256-CBC.

    A fresh random 16-byte IV is generated for every call and prepended
    to the ciphertext. The caller does not manage IVs.

    Args:
        plaintext: Arbitrary-length bytes to encrypt.
        key: Exactly 32 bytes (AES-256 key, typically from DH session).

    Returns:
        IV (16 bytes) || ciphertext (multiple of 16 bytes).

    Raises:
        ValueError: If key is not 32 bytes.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key. Got {len(key)} bytes.")

    iv = secrets.token_bytes(16)
    round_keys = _key_expansion(key)
    padded = _pkcs7_pad(plaintext)

    ciphertext = b""
    prev_block = iv
    for i in range(0, len(padded), 16):
        block = bytes(
            padded[i + j] ^ prev_block[j] for j in range(16)
        )
        encrypted_block = _aes_encrypt_block(block, round_keys)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext produced by aes_encrypt().

    Expects IV (first 16 bytes) prepended to the ciphertext.

    Args:
        ciphertext: IV || ciphertext bytes from aes_encrypt().
        key: Exactly 32 bytes (same key used for encryption).

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If key is not 32 bytes, ciphertext is too short,
                    ciphertext length is invalid, or padding is corrupt.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key. Got {len(key)} bytes.")
    if len(ciphertext) < 32:
        raise ValueError("Ciphertext too short — must be at least IV (16) + one block (16).")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes.")

    iv = ciphertext[:16]
    ct = ciphertext[16:]
    round_keys = _key_expansion(key)

    plaintext_padded = b""
    prev_block = iv
    for i in range(0, len(ct), 16):
        block = ct[i : i + 16]
        decrypted_block = _aes_decrypt_block(block, round_keys)
        plaintext_padded += bytes(
            decrypted_block[j] ^ prev_block[j] for j in range(16)
        )
        prev_block = block

    return _pkcs7_unpad(plaintext_padded)