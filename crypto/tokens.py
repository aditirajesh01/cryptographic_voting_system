"""
crypto/tokens.py

Anti-replay token generation and server-side validation.

Each voter session is issued a unique one-time token. The server rejects
any message that arrives with a token it has already seen or that has
expired — preventing replay attacks regardless of encryption strength.

Token format (64 bytes total):
    32 bytes: cryptographically random token value
    32 bytes: HMAC-SHA256(server_secret, token_value || expiry_timestamp)

The HMAC prevents forgery. The registry prevents replay.

Usage:
    from crypto.tokens import TokenManager

    manager = TokenManager()
    token   = manager.issue()             # Issue to voter at session start
    valid   = manager.consume(token)      # Call when vote arrives; True = valid
"""

import hashlib
import hmac
import secrets
import time


# Token lifetime in seconds — voter must cast vote within this window
DEFAULT_TTL_SECONDS = 300  # 5 minutes


class TokenManager:
    """
    Server-side token manager.

    One instance per server — shared across all voter sessions.
    Thread safety: the caller (server.py) is responsible for locking
    if multiple threads call issue()/consume() concurrently. The
    operations themselves are atomic at the Python level due to the GIL,
    but compound check-then-act patterns require external locking.
    """

    def __init__(self, ttl: int = DEFAULT_TTL_SECONDS):
        """
        Args:
            ttl: Token lifetime in seconds. Tokens older than this are rejected.
        """
        if ttl <= 0:
            raise ValueError(f"TTL must be positive. Got {ttl}.")
        self._ttl: int = ttl
        self._secret: bytes = secrets.token_bytes(32)  # Server-side HMAC key
        self._issued:   set[bytes] = set()   # All issued token values
        self._consumed: set[bytes] = set()   # Consumed (used) token values

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue(self) -> bytes:
        """
        Issue a new one-time token for a voter session.

        Returns:
            64-byte token: random_value (32) || HMAC (32).
            Send this to the voter; they must include it with their vote.
        """
        token_value = secrets.token_bytes(32)
        expiry      = int(time.time()) + self._ttl
        mac         = self._compute_mac(token_value, expiry)

        # Encode expiry into the token so the server can verify it later
        # Full token: token_value (32) || expiry (8, big-endian) || mac (32)
        token = token_value + expiry.to_bytes(8, byteorder="big") + mac
        self._issued.add(token_value)
        return token

    def consume(self, token: bytes) -> bool:
        """
        Validate and consume a token.

        A token is valid if:
          1. It is exactly 72 bytes long.
          2. Its HMAC is correct (not forged).
          3. It has not expired.
          4. It has been issued by this server.
          5. It has not been consumed before (replay check).

        Consuming a valid token marks it as used — subsequent calls
        with the same token return False.

        Args:
            token: 72-byte token from the voter.

        Returns:
            True if valid and not previously consumed. False otherwise.
        """
        if len(token) != 72:
            return False

        token_value = token[:32]
        expiry_bytes = token[32:40]
        received_mac = token[40:]

        try:
            expiry = int.from_bytes(expiry_bytes, byteorder="big")
        except Exception:
            return False

        # Check expiry
        if int(time.time()) > expiry:
            return False

        # Verify HMAC — constant-time comparison
        expected_mac = self._compute_mac(token_value, expiry)
        if not secrets.compare_digest(expected_mac, received_mac):
            return False

        # Check token was issued by this server
        if token_value not in self._issued:
            return False

        # Replay check
        if token_value in self._consumed:
            return False

        # Mark as consumed
        self._consumed.add(token_value)
        return True

    def revoke(self, token: bytes) -> bool:
        """
        Revoke an issued token without consuming it (e.g. session cancelled).

        Args:
            token: 72-byte token to revoke.

        Returns:
            True if the token was found and revoked, False if not found.
        """
        if len(token) != 72:
            return False
        token_value = token[:32]
        if token_value in self._issued:
            self._consumed.add(token_value)  # Mark consumed so it can't be used
            return True
        return False

    def purge_expired(self) -> int:
        """
        Remove expired tokens from the issued set to free memory.
        Safe to call periodically on long-running servers.

        Returns:
            Number of tokens purged.
        """
        # We can't recover expiry from token_value alone without the full token,
        # so we purge all consumed tokens from issued (they're already spent).
        before = len(self._issued)
        self._issued -= self._consumed
        return before - len(self._issued)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_mac(self, token_value: bytes, expiry: int) -> bytes:
        """
        Compute HMAC-SHA256 over token_value || expiry.

        Args:
            token_value: 32-byte random token value.
            expiry:      Unix timestamp of expiry.

        Returns:
            32-byte HMAC digest.
        """
        message = token_value + expiry.to_bytes(8, byteorder="big")
        return hmac.new(self._secret, message, hashlib.sha256).digest()