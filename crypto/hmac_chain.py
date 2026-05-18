"""
crypto/hmac_chain.py

Tamper-evident HMAC audit chain for vote logging.

Each entry in the chain is:
    HMAC-SHA256(chain_key, prev_hmac || sequence || timestamp || data)

The chain starts with a genesis entry whose prev_hmac is 32 zero bytes.
Any modification to any entry invalidates all subsequent HMACs.

This module is pure crypto — no database calls.
Persistence (reading/writing entries) is handled by db.py.

Usage:
    from crypto.hmac_chain import HMACChain

    key   = HMACChain.generate_chain_key()
    chain = HMACChain(key)

    entry1 = chain.append(b"vote:candidate_1")
    entry2 = chain.append(b"vote:candidate_2")

    is_valid = chain.verify(chain.entries)
"""

import hashlib
import hmac
import secrets
import time
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Chain entry type
# ---------------------------------------------------------------------------

class ChainEntry(NamedTuple):
    sequence:  int    # 0-indexed position in chain
    timestamp: int    # Unix timestamp (seconds)
    data:      bytes  # Vote payload or audit event
    hmac:      bytes  # 32-byte HMAC of this entry


# ---------------------------------------------------------------------------
# HMAC chain
# ---------------------------------------------------------------------------

class HMACChain:
    """
    Append-only HMAC chain.

    Each entry's HMAC is computed over:
        prev_hmac || sequence (8 bytes big-endian) || timestamp (8 bytes big-endian) || data

    The genesis prev_hmac is 32 zero bytes.
    """

    GENESIS_HMAC = b"\x00" * 32

    def __init__(self, chain_key: bytes):
        """
        Args:
            chain_key: 32-byte secret key for HMAC computation.
                       Must be the same key used for verification.

        Raises:
            ValueError: If chain_key is not 32 bytes.
        """
        if len(chain_key) != 32:
            raise ValueError(
                f"Chain key must be 32 bytes. Got {len(chain_key)}."
            )
        self._key: bytes = chain_key
        self.entries: list[ChainEntry] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def generate_chain_key() -> bytes:
        """
        Generate a fresh 32-byte chain key using CSPRNG.
        Call once at server startup and store securely in memory.

        Returns:
            32 random bytes.
        """
        return secrets.token_bytes(32)

    def append(self, data: bytes) -> ChainEntry:
        """
        Append a new entry to the chain.

        Args:
            data: Arbitrary bytes representing the audit event
                  (e.g. encrypted vote payload).

        Returns:
            The newly created ChainEntry.
        """
        sequence  = len(self.entries)
        timestamp = int(time.time())
        prev_hmac = self.entries[-1].hmac if self.entries else self.GENESIS_HMAC
        entry_hmac = self._compute_hmac(prev_hmac, sequence, timestamp, data)

        entry = ChainEntry(
            sequence=sequence,
            timestamp=timestamp,
            data=data,
            hmac=entry_hmac,
        )
        self.entries.append(entry)
        return entry

    def verify(self, entries: list[ChainEntry]) -> bool:
        """
        Verify the integrity of the entire chain.

        Recomputes every HMAC from scratch and checks that:
          1. Each HMAC matches the stored HMAC.
          2. Each entry's prev_hmac links correctly to the previous entry.
          3. Sequence numbers are consecutive starting from 0.

        Args:
            entries: List of ChainEntry objects to verify.
                     Typically chain.entries or entries loaded from DB.

        Returns:
            True if the chain is intact, False if any tampering is detected.
        """
        if not entries:
            return True  # Empty chain is trivially valid

        prev_hmac = self.GENESIS_HMAC

        for expected_seq, entry in enumerate(entries):
            # Sequence must be consecutive
            if entry.sequence != expected_seq:
                return False

            # Recompute HMAC and compare
            computed = self._compute_hmac(
                prev_hmac,
                entry.sequence,
                entry.timestamp,
                entry.data,
            )
            if not secrets.compare_digest(computed, entry.hmac):
                return False

            prev_hmac = entry.hmac

        return True

    def get_chain_tip(self) -> bytes:
        """
        Return the HMAC of the last entry (the chain tip).
        Used to efficiently verify that a new entry chains correctly.

        Returns:
            32-byte HMAC of the last entry, or GENESIS_HMAC if chain is empty.
        """
        if not self.entries:
            return self.GENESIS_HMAC
        return self.entries[-1].hmac

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_hmac(
        self,
        prev_hmac: bytes,
        sequence: int,
        timestamp: int,
        data: bytes,
    ) -> bytes:
        """
        Compute HMAC-SHA256 for one chain entry.

        Message format:
            prev_hmac (32 bytes)
            || sequence (8 bytes, big-endian)
            || timestamp (8 bytes, big-endian)
            || data (variable)

        Args:
            prev_hmac: HMAC of the previous entry (or GENESIS_HMAC).
            sequence:  Position of this entry in the chain.
            timestamp: Unix timestamp of this entry.
            data:      Entry payload bytes.

        Returns:
            32-byte HMAC digest.
        """
        message = (
            prev_hmac
            + sequence.to_bytes(8, byteorder="big")
            + timestamp.to_bytes(8, byteorder="big")
            + data
        )
        return hmac.new(self._key, message, hashlib.sha256).digest()