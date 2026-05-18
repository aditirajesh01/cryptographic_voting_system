"""
crypto/dh.py

Diffie-Hellman key exchange using RFC 3526 Group 14 (2048-bit MODP).
Produces a 32-byte AES-256 session key via HKDF-SHA256.

Usage:
    dh = DHKeyExchange()
    public_key = dh.get_public_key()          # send this to the other party
    session_key = dh.derive_session_key(their_public_key)  # call once
"""

import secrets
import hashlib
import hmac


# ---------------------------------------------------------------------------
# RFC 3526 Group 14 — 2048-bit MODP parameters
# Source: https://www.rfc-editor.org/rfc/rfc3526#section-3
# ---------------------------------------------------------------------------

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

G = 2

# Private key bit length — must be at least 2 * security_level bits.
# 256 bits gives 128-bit security, which matches AES-256.
_PRIVATE_KEY_BITS = 256


class DHKeyExchange:
    """
    One instance = one key exchange session.
    Instantiate fresh for every new voter connection.
    """

    def __init__(self):
        self._private_key: int = self._generate_private_key()
        self._public_key: int = pow(G, self._private_key, P)
        self._session_key: bytes | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_public_key(self) -> int:
        """Return this party's DH public key (send this to the peer)."""
        return self._public_key

    def derive_session_key(self, peer_public_key: int) -> bytes:
        """
        Compute the shared secret from the peer's public key and derive
        a 32-byte AES-256 session key via HKDF-SHA256.

        Call this exactly once per session after receiving the peer's
        public key. The result is cached — repeated calls return the
        same key without recomputing.

        Args:
            peer_public_key: The other party's DH public key as an integer.

        Returns:
            32-byte session key suitable for AES-256.

        Raises:
            ValueError: If the peer public key fails validation.
        """
        if self._session_key is not None:
            return self._session_key

        self._validate_peer_public_key(peer_public_key)

        shared_secret: int = pow(peer_public_key, self._private_key, P)

        # Convert shared secret to bytes (big-endian, fixed 256-byte width)
        shared_secret_bytes: bytes = shared_secret.to_bytes(256, byteorder="big")

        self._session_key = _hkdf_sha256(
            input_key_material=shared_secret_bytes,
            length=32,
            info=b"cryptographic_voting_system_session_key",
        )
        return self._session_key

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_private_key() -> int:
        """
        Generate a cryptographically secure private key in [2, P-2].
        Uses secrets.randbits — backed by OS CSPRNG (/dev/urandom on macOS).
        """
        while True:
            candidate = secrets.randbits(_PRIVATE_KEY_BITS)
            if 2 <= candidate <= P - 2:
                return candidate

    @staticmethod
    def _validate_peer_public_key(key: int) -> None:
        """
        Validate peer public key to prevent small-subgroup attacks.

        Checks:
          1. key is in range [2, P-2]
          2. key^((P-1)/2) mod P == 1  — key is in the correct subgroup
             (P is a safe prime, so (P-1)/2 is also prime; this check
              ensures the peer's key has the expected large-order subgroup)
        """
        if not isinstance(key, int):
            raise ValueError("Peer public key must be an integer.")
        if not (2 <= key <= P - 2):
            raise ValueError(
                f"Peer public key out of valid range [2, P-2]. Got: {key}"
            )
        q = (P - 1) // 2
        if pow(key, q, P) != 1:
            raise ValueError(
                "Peer public key failed subgroup validation. "
                "Possible small-subgroup attack."
            )


# ---------------------------------------------------------------------------
# HKDF-SHA256
# RFC 5869 — two-step: extract then expand.
# Implemented from scratch; no external library.
# ---------------------------------------------------------------------------

def _hkdf_sha256(
    input_key_material: bytes,
    length: int,
    info: bytes = b"",
    salt: bytes | None = None,
) -> bytes:
    """
    HKDF using SHA-256 as the hash function (RFC 5869).

    Args:
        input_key_material: Raw shared secret bytes.
        length: Desired output key length in bytes (max 255 * 32).
        info: Context/application-specific info string.
        salt: Optional salt. Defaults to HashLen zero bytes per RFC 5869.

    Returns:
        Derived key of `length` bytes.
    """
    hash_len = 32  # SHA-256 output size

    if length > 255 * hash_len:
        raise ValueError(
            f"Requested HKDF output length {length} exceeds maximum "
            f"{255 * hash_len} bytes for SHA-256."
        )

    # Step 1 — Extract: PRK = HMAC-SHA256(salt, IKM)
    if salt is None:
        salt = b"\x00" * hash_len
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()

    # Step 2 — Expand: T(1) || T(2) || ... until we have `length` bytes
    okm = b""
    t_prev = b""
    for i in range(1, -(-length // hash_len) + 1):  # ceil(length / hash_len)
        t_prev = hmac.new(
            prk,
            t_prev + info + bytes([i]),
            hashlib.sha256,
        ).digest()
        okm += t_prev

    return okm[:length]