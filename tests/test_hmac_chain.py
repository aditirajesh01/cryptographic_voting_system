"""
tests/test_hmac_chain.py

Unit tests for crypto/hmac_chain.py

Run with:
    python -m pytest tests/test_hmac_chain.py -v
"""

import pytest
import time
from crypto.hmac_chain import HMACChain, ChainEntry


@pytest.fixture
def key():
    return HMACChain.generate_chain_key()


@pytest.fixture
def chain(key):
    return HMACChain(key)


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------

class TestChainKeyGeneration:

    def test_key_is_32_bytes(self):
        assert len(HMACChain.generate_chain_key()) == 32

    def test_key_is_bytes(self):
        assert isinstance(HMACChain.generate_chain_key(), bytes)

    def test_keys_are_unique(self):
        keys = {HMACChain.generate_chain_key() for _ in range(20)}
        assert len(keys) == 20

    def test_invalid_key_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            HMACChain(b"tooshort")


# ---------------------------------------------------------------------------
# Append tests
# ---------------------------------------------------------------------------

class TestAppend:

    def test_append_returns_chain_entry(self, chain):
        entry = chain.append(b"vote:candidate_1")
        assert isinstance(entry, ChainEntry)

    def test_first_entry_sequence_is_zero(self, chain):
        entry = chain.append(b"vote:candidate_1")
        assert entry.sequence == 0

    def test_sequences_increment(self, chain):
        for i in range(5):
            entry = chain.append(f"vote:{i}".encode())
            assert entry.sequence == i

    def test_hmac_is_32_bytes(self, chain):
        entry = chain.append(b"data")
        assert len(entry.hmac) == 32

    def test_hmac_is_bytes(self, chain):
        entry = chain.append(b"data")
        assert isinstance(entry.hmac, bytes)

    def test_entries_accumulate(self, chain):
        for i in range(5):
            chain.append(f"event_{i}".encode())
        assert len(chain.entries) == 5

    def test_different_data_produces_different_hmac(self, chain):
        e1 = chain.append(b"vote:candidate_1")
        e2 = chain.append(b"vote:candidate_2")
        assert e1.hmac != e2.hmac

    def test_timestamp_is_recent(self, chain):
        before = int(time.time())
        entry = chain.append(b"data")
        after = int(time.time())
        assert before <= entry.timestamp <= after


# ---------------------------------------------------------------------------
# Verify tests
# ---------------------------------------------------------------------------

class TestVerify:

    def test_empty_chain_is_valid(self, chain):
        assert chain.verify([]) is True

    def test_single_entry_valid(self, chain):
        chain.append(b"vote:candidate_1")
        assert chain.verify(chain.entries) is True

    def test_multiple_entries_valid(self, chain):
        for i in range(10):
            chain.append(f"vote:{i}".encode())
        assert chain.verify(chain.entries) is True

    def test_tampered_data_detected(self, chain):
        chain.append(b"vote:candidate_1")
        chain.append(b"vote:candidate_2")

        # Tamper with the data in the first entry
        tampered = list(chain.entries)
        original = tampered[0]
        tampered[0] = ChainEntry(
            sequence=original.sequence,
            timestamp=original.timestamp,
            data=b"vote:candidate_TAMPERED",
            hmac=original.hmac,
        )
        assert chain.verify(tampered) is False

    def test_tampered_hmac_detected(self, chain):
        chain.append(b"vote:candidate_1")

        tampered = list(chain.entries)
        original = tampered[0]
        bad_hmac = bytes(b ^ 0xFF for b in original.hmac)
        tampered[0] = ChainEntry(
            sequence=original.sequence,
            timestamp=original.timestamp,
            data=original.data,
            hmac=bad_hmac,
        )
        assert chain.verify(tampered) is False

    def test_tampered_timestamp_detected(self, chain):
        chain.append(b"vote:candidate_1")

        tampered = list(chain.entries)
        original = tampered[0]
        tampered[0] = ChainEntry(
            sequence=original.sequence,
            timestamp=original.timestamp + 9999,
            data=original.data,
            hmac=original.hmac,
        )
        assert chain.verify(tampered) is False

    def test_wrong_sequence_detected(self, chain):
        chain.append(b"vote:candidate_1")
        chain.append(b"vote:candidate_2")

        # Swap sequence numbers
        tampered = list(chain.entries)
        e0, e1 = tampered[0], tampered[1]
        tampered[0] = ChainEntry(1, e0.timestamp, e0.data, e0.hmac)
        tampered[1] = ChainEntry(0, e1.timestamp, e1.data, e1.hmac)
        assert chain.verify(tampered) is False

    def test_reordered_entries_detected(self, chain):
        chain.append(b"vote:candidate_1")
        chain.append(b"vote:candidate_2")
        chain.append(b"vote:candidate_3")

        # Reverse the order
        assert chain.verify(list(reversed(chain.entries))) is False

    def test_deleted_middle_entry_detected(self, chain):
        for i in range(5):
            chain.append(f"vote:{i}".encode())

        # Remove entry at index 2
        tampered = chain.entries[:2] + chain.entries[3:]
        assert chain.verify(tampered) is False

    def test_wrong_key_fails_verification(self, chain):
        for i in range(3):
            chain.append(f"vote:{i}".encode())

        wrong_key_chain = HMACChain(HMACChain.generate_chain_key())
        assert wrong_key_chain.verify(chain.entries) is False

    def test_duplicated_entry_detected(self, chain):
        chain.append(b"vote:candidate_1")
        chain.append(b"vote:candidate_2")

        # Duplicate first entry
        tampered = [chain.entries[0]] + list(chain.entries)
        assert chain.verify(tampered) is False


# ---------------------------------------------------------------------------
# Chain tip tests
# ---------------------------------------------------------------------------

class TestChainTip:

    def test_empty_chain_tip_is_genesis(self, chain):
        assert chain.get_chain_tip() == HMACChain.GENESIS_HMAC

    def test_tip_updates_after_append(self, chain):
        chain.append(b"event_1")
        tip1 = chain.get_chain_tip()
        chain.append(b"event_2")
        tip2 = chain.get_chain_tip()
        assert tip1 != tip2

    def test_tip_matches_last_entry_hmac(self, chain):
        for i in range(5):
            chain.append(f"event_{i}".encode())
        assert chain.get_chain_tip() == chain.entries[-1].hmac