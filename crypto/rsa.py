"""
crypto/rsa.py

RSA-2048 implemented from scratch.

Covers:
  - Probabilistic prime generation (Miller-Rabin, 20 rounds)
  - Key pair generation (e = 65537, 2048-bit modulus)
  - Raw RSA encrypt / decrypt (used for challenge-response auth)
  - PKCS#1 v1.5 signature / verification (used for vote integrity)

No external crypto libraries used.

Usage:
    from crypto.rsa import generate_keypair, rsa_encrypt, rsa_decrypt
    from crypto.rsa import rsa_sign, rsa_verify

    pub, priv = generate_keypair()
    ciphertext = rsa_encrypt(b"challenge_token", pub)
    plaintext  = rsa_decrypt(ciphertext, priv)

    signature  = rsa_sign(b"message", priv)
    valid      = rsa_verify(b"message", signature, pub)
"""

import secrets
import hashlib
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Key types
# ---------------------------------------------------------------------------

class RSAPublicKey(NamedTuple):
    n: int  # modulus
    e: int  # public exponent (always 65537)


class RSAPrivateKey(NamedTuple):
    n: int  # modulus
    d: int  # private exponent
    p: int  # prime factor p
    q: int  # prime factor q


# ---------------------------------------------------------------------------
# Integer arithmetic helpers
# ---------------------------------------------------------------------------

def _mod_inverse(a: int, m: int) -> int:
    """
    Compute modular inverse of a mod m using the extended Euclidean algorithm.

    Raises:
        ValueError: If the inverse does not exist (gcd(a, m) != 1).
    """
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) where a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------------------
# Miller-Rabin primality test
# ---------------------------------------------------------------------------

def _miller_rabin(n: int, rounds: int = 20) -> bool:
    """
    Probabilistic primality test using Miller-Rabin.

    False positive probability: at most 4^(-rounds).
    With rounds=20, this is below 10^(-12) — sufficient for key generation.

    Args:
        n: Integer to test.
        rounds: Number of witness rounds.

    Returns:
        True if n is probably prime, False if definitely composite.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Small prime fast path
    small_primes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # random in [2, n-2]
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite

    return True  # probably prime


def _generate_prime(bits: int) -> int:
    """
    Generate a random prime of exactly `bits` bits.

    Sets the top two bits and bottom bit to ensure:
      - Exact bit length
      - Odd number (required for primality)
      - Product of two such primes has the expected bit length

    Args:
        bits: Desired bit length (e.g. 1024 for RSA-2048).

    Returns:
        A probable prime of the specified bit length.
    """
    while True:
        # Generate random odd number with top two bits set
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1  # top 2 bits + odd
        if _miller_rabin(candidate):
            return candidate


# ---------------------------------------------------------------------------
# RSA key generation
# ---------------------------------------------------------------------------

E = 65537  # Standard public exponent


def generate_keypair(bits: int = 2048) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Generate an RSA key pair.

    Args:
        bits: RSA modulus size in bits. Default 2048. Must be even.

    Returns:
        (RSAPublicKey, RSAPrivateKey) tuple.

    Raises:
        ValueError: If bits is not even or less than 512.
    """
    if bits < 512 or bits % 2 != 0:
        raise ValueError(f"Key size must be even and >= 512 bits. Got {bits}.")

    half = bits // 2

    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)

        # Ensure p != q and |p - q| is large enough
        if p == q:
            continue
        if abs(p - q).bit_length() < half // 2:
            continue  # Too close — vulnerable to Fermat factorization

        n = p * q
        phi_n = (p - 1) * (q - 1)

        # e must be coprime with phi(n)
        if _gcd(E, phi_n) != 1:
            continue

        d = _mod_inverse(E, phi_n)

        pub  = RSAPublicKey(n=n, e=E)
        priv = RSAPrivateKey(n=n, d=d, p=p, q=q)
        return pub, priv


# ---------------------------------------------------------------------------
# Raw RSA encrypt / decrypt
# Used for challenge-response: server encrypts a random challenge with
# voter's public key; voter decrypts and returns it to prove key ownership.
# ---------------------------------------------------------------------------

def rsa_encrypt(message: bytes, public_key: RSAPublicKey) -> bytes:
    """
    Encrypt a short message with RSA public key (textbook RSA, OAEP-like padding).

    Uses PKCS#1 v1.5 encryption padding.

    Args:
        message: Plaintext bytes. Must be <= key_bytes - 11.
        public_key: RSAPublicKey (n, e).

    Returns:
        Ciphertext as bytes, same length as the RSA modulus.

    Raises:
        ValueError: If message is too long.
    """
    k = (public_key.n.bit_length() + 7) // 8  # key size in bytes
    max_msg_len = k - 11

    if len(message) > max_msg_len:
        raise ValueError(
            f"Message too long for RSA-{public_key.n.bit_length()} "
            f"with PKCS#1 v1.5 padding. Max {max_msg_len} bytes, got {len(message)}."
        )

    # PKCS#1 v1.5 encryption padding: 0x00 || 0x02 || PS || 0x00 || M
    ps_len = k - len(message) - 3
    # PS must be non-zero random bytes
    ps = b""
    while len(ps) < ps_len:
        chunk = secrets.token_bytes(ps_len * 2)
        ps += bytes(b for b in chunk if b != 0)
    ps = ps[:ps_len]

    padded = b"\x00\x02" + ps + b"\x00" + message
    m_int = int.from_bytes(padded, byteorder="big")
    c_int = pow(m_int, public_key.e, public_key.n)
    return c_int.to_bytes(k, byteorder="big")


def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Decrypt RSA ciphertext with private key.

    Args:
        ciphertext: Bytes produced by rsa_encrypt().
        private_key: RSAPrivateKey (n, d, p, q).

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If padding is invalid.
    """
    k = (private_key.n.bit_length() + 7) // 8
    c_int = int.from_bytes(ciphertext, byteorder="big")
    m_int = pow(c_int, private_key.d, private_key.n)
    padded = m_int.to_bytes(k, byteorder="big")

    # Validate and strip PKCS#1 v1.5 padding
    if padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 padding: incorrect header bytes.")

    # Find the 0x00 separator after the padding string
    sep_idx = padded.find(b"\x00", 2)
    if sep_idx == -1 or sep_idx < 10:  # PS must be at least 8 bytes
        raise ValueError("Invalid PKCS#1 v1.5 padding: separator not found or PS too short.")

    return padded[sep_idx + 1:]


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 signature / verification
# Used for vote integrity: server signs the accepted vote record.
# ---------------------------------------------------------------------------

def rsa_sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign a message using RSA with PKCS#1 v1.5 signature padding and SHA-256.

    Computes: signature = (PKCS1_v1.5_pad(SHA256(message)))^d mod n

    Args:
        message: Arbitrary-length bytes to sign.
        private_key: RSAPrivateKey.

    Returns:
        Signature bytes, same length as the RSA modulus.
    """
    k = (private_key.n.bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()

    # SHA-256 DER-encoded DigestInfo prefix (RFC 3447)
    sha256_der_prefix = bytes.fromhex(
        "3031300d060960864801650304020105000420"
    )
    digest_info = sha256_der_prefix + digest

    # PKCS#1 v1.5 signature padding: 0x00 || 0x01 || PS || 0x00 || DigestInfo
    ps_len = k - len(digest_info) - 3
    if ps_len < 8:
        raise ValueError("RSA key too small for PKCS#1 v1.5 signature with SHA-256.")

    padded = b"\x00\x01" + b"\xFF" * ps_len + b"\x00" + digest_info
    m_int = int.from_bytes(padded, byteorder="big")
    s_int = pow(m_int, private_key.d, private_key.n)
    return s_int.to_bytes(k, byteorder="big")


def rsa_verify(message: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """
    Verify an RSA signature.

    Args:
        message: The original message bytes.
        signature: Signature bytes from rsa_sign().
        public_key: RSAPublicKey.

    Returns:
        True if the signature is valid, False otherwise.
    """
    k = (public_key.n.bit_length() + 7) // 8

    try:
        s_int = int.from_bytes(signature, byteorder="big")
        m_int = pow(s_int, public_key.e, public_key.n)
        padded = m_int.to_bytes(k, byteorder="big")

        if padded[0] != 0x00 or padded[1] != 0x01:
            return False

        sep_idx = padded.find(b"\x00", 2)
        if sep_idx == -1:
            return False

        # Verify all padding bytes are 0xFF
        if padded[2:sep_idx] != b"\xFF" * (sep_idx - 2):
            return False

        digest_info = padded[sep_idx + 1:]
        sha256_der_prefix = bytes.fromhex(
            "3031300d060960864801650304020105000420"
        )

        if not digest_info.startswith(sha256_der_prefix):
            return False

        extracted_digest = digest_info[len(sha256_der_prefix):]
        expected_digest  = hashlib.sha256(message).digest()

        # Constant-time comparison to prevent timing attacks
        return secrets.compare_digest(extracted_digest, expected_digest)

    except Exception:
        return False