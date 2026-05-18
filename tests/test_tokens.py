"""
tests/test_tokens.py

Unit tests for crypto/tokens.py

Run with:
    python -m pytest tests/test_tokens.py -v
"""

import pytest
import time
from crypto.tokens import TokenManager, DEFAULT_TTL_SECONDS


@pytest.fixture
def manager():
    return TokenManager()


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

class TestInit:

    def test_default_ttl(self):
        m = TokenManager()
        assert m._ttl == DEFAULT_TTL_SECONDS

    def test_custom_ttl(self):
        m = TokenManager(ttl=60)
        assert m._ttl == 60

    def test_invalid_ttl_raises(self):
        with pytest.raises(ValueError, match="positive"):
            TokenManager(ttl=0)

    def test_negative_ttl_raises(self):
        with pytest.raises(ValueError, match="positive"):
            TokenManager(ttl=-1)

    def test_secret_is_32_bytes(self):
        m = TokenManager()
        assert len(m._secret) == 32

    def test_different_instances_have_different_secrets(self):
        assert TokenManager()._secret != TokenManager()._secret


# ---------------------------------------------------------------------------
# Issue tests
# ---------------------------------------------------------------------------

class TestIssue:

    def test_token_is_bytes(self, manager):
        assert isinstance(manager.issue(), bytes)

    def test_token_is_72_bytes(self, manager):
        assert len(manager.issue()) == 72

    def test_tokens_are_unique(self, manager):
        tokens = {manager.issue() for _ in range(100)}
        assert len(tokens) == 100

    def test_issued_token_tracked(self, manager):
        token = manager.issue()
        assert token[:32] in manager._issued


# ---------------------------------------------------------------------------
# Consume tests
# ---------------------------------------------------------------------------

class TestConsume:

    def test_valid_token_consumed(self, manager):
        token = manager.issue()
        assert manager.consume(token) is True

    def test_replay_rejected(self, manager):
        token = manager.issue()
        manager.consume(token)
        assert manager.consume(token) is False

    def test_unconsumed_token_stays_valid(self, manager):
        token = manager.issue()
        # Don't consume — should still be valid
        assert manager.consume(token) is True

    def test_wrong_length_rejected(self, manager):
        assert manager.consume(b"tooshort") is False

    def test_empty_bytes_rejected(self, manager):
        assert manager.consume(b"") is False

    def test_forged_token_rejected(self, manager):
        """A randomly generated token not issued by this manager must be rejected."""
        import secrets as sec
        fake_token = sec.token_bytes(72)
        assert manager.consume(fake_token) is False

    def test_tampered_mac_rejected(self, manager):
        token = bytearray(manager.issue())
        token[40] ^= 0xFF  # Flip a bit in the MAC portion
        assert manager.consume(bytes(token)) is False

    def test_tampered_value_rejected(self, manager):
        token = bytearray(manager.issue())
        token[0] ^= 0xFF  # Flip a bit in the token value
        assert manager.consume(bytes(token)) is False

    def test_expired_token_rejected(self):
        """Token with TTL=1 second must be rejected after expiry."""
        manager = TokenManager(ttl=1)
        token = manager.issue()
        time.sleep(2)
        assert manager.consume(token) is False

    def test_token_from_different_manager_rejected(self):
        """Token issued by one manager must be rejected by another."""
        m1 = TokenManager()
        m2 = TokenManager()
        token = m1.issue()
        assert m2.consume(token) is False

    def test_multiple_voters_independent(self, manager):
        """Each voter's token is independent."""
        tokens = [manager.issue() for _ in range(10)]
        for token in tokens:
            assert manager.consume(token) is True

    def test_consume_returns_false_not_raises_on_garbage(self, manager):
        """consume() must never raise — bad input returns False."""
        assert manager.consume(b"\x00" * 72) is False


# ---------------------------------------------------------------------------
# Revoke tests
# ---------------------------------------------------------------------------

class TestRevoke:

    def test_revoke_prevents_consumption(self, manager):
        token = manager.issue()
        manager.revoke(token)
        assert manager.consume(token) is False

    def test_revoke_unknown_token_returns_false(self, manager):
        import secrets as sec
        fake = sec.token_bytes(72)
        assert manager.revoke(fake) is False

    def test_revoke_returns_true_for_valid_token(self, manager):
        token = manager.issue()
        assert manager.revoke(token) is True


# ---------------------------------------------------------------------------
# Purge tests
# ---------------------------------------------------------------------------

class TestPurge:

    def test_purge_removes_consumed(self, manager):
        tokens = [manager.issue() for _ in range(5)]
        for t in tokens:
            manager.consume(t)
        purged = manager.purge_expired()
        assert purged == 5

    def test_purge_leaves_unconsumed(self, manager):
        tokens = [manager.issue() for _ in range(5)]
        manager.consume(tokens[0])  # consume only one
        manager.purge_expired()
        # Remaining unconsumed tokens should still be consumable
        for t in tokens[1:]:
            assert manager.consume(t) is True