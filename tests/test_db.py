"""
tests/test_db.py

Unit tests for db.py

Uses SQLite in-memory database — no files written to disk.

Run with:
    python -m pytest tests/test_db.py -v
"""

import pytest
from db import Database
from crypto.hmac_chain import HMACChain, ChainEntry


@pytest.fixture
def db():
    """Fresh in-memory database for each test."""
    d = Database(":memory:")
    d.init_schema()
    return d


@pytest.fixture
def chain():
    key = HMACChain.generate_chain_key()
    return HMACChain(key)


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

class TestSchema:

    def test_init_schema_idempotent(self):
        """Calling init_schema twice must not raise."""
        d = Database(":memory:")
        d.init_schema()
        d.init_schema()

    def test_empty_db_vote_count_zero(self, db):
        assert db.get_vote_count() == 0

    def test_empty_db_chain_length_zero(self, db):
        assert db.get_audit_chain_length() == 0


# ---------------------------------------------------------------------------
# Voter registration tests
# ---------------------------------------------------------------------------

class TestVoterRegistry:

    def test_register_and_retrieve(self, db):
        db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=12345, e=65537)
        voter = db.get_voter("voter_001")
        assert voter is not None
        assert voter["voter_id"] == "voter_001"
        assert voter["rsa_n"] == 12345
        assert voter["rsa_e"] == 65537
        assert voter["has_voted"] is False

    def test_duplicate_registration_raises(self, db):
        db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=12345, e=65537)
        with pytest.raises(ValueError, match="already registered"):
            db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=99999, e=65537)

    def test_voter_exists_true(self, db):
        db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=12345, e=65537)
        assert db.voter_exists("voter_001") is True

    def test_voter_exists_false(self, db):
        assert db.voter_exists("nonexistent") is False

    def test_get_voter_not_found_returns_none(self, db):
        assert db.get_voter("ghost") is None

    def test_multiple_voters(self, db):
        for i in range(5):
            db.register_voter(f"voter_{i:03d}", name="Test Voter", constituency="Test District", n=i + 1000, e=65537)
        voters = db.get_all_voters()
        assert len(voters) == 5

    def test_rsa_n_large_integer_preserved(self, db):
        """RSA modulus is a 2048-bit integer — must survive DB round-trip."""
        large_n = 2**2047 + 1
        db.register_voter("voter_large", name="Test Voter", constituency="Test District", n=large_n, e=65537)
        voter = db.get_voter("voter_large")
        assert voter["rsa_n"] == large_n


# ---------------------------------------------------------------------------
# Mark voted tests
# ---------------------------------------------------------------------------

class TestMarkVoted:

    def test_mark_voted_sets_flag(self, db):
        db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=12345, e=65537)
        db.mark_voted("voter_001")
        assert db.has_voted("voter_001") is True

    def test_double_vote_raises(self, db):
        db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=12345, e=65537)
        db.mark_voted("voter_001")
        with pytest.raises(ValueError, match="already voted"):
            db.mark_voted("voter_001")

    def test_mark_voted_unknown_voter_raises(self, db):
        with pytest.raises(ValueError, match="not found"):
            db.mark_voted("ghost")

    def test_has_voted_false_before_voting(self, db):
        db.register_voter("voter_001", name="Test Voter", constituency="Test District", n=12345, e=65537)
        assert db.has_voted("voter_001") is False

    def test_has_voted_unknown_voter_returns_false(self, db):
        assert db.has_voted("ghost") is False


# ---------------------------------------------------------------------------
# Vote storage tests
# ---------------------------------------------------------------------------

class TestVoteStorage:

    def test_store_vote_increments_count(self, db, chain):
        entry = chain.append(b"vote:candidate_1")
        db.store_vote(b"encrypted_payload", entry)
        assert db.get_vote_count() == 1

    def test_store_multiple_votes(self, db, chain):
        for i in range(5):
            entry = chain.append(f"vote:{i}".encode())
            db.store_vote(f"enc_{i}".encode(), entry)
        assert db.get_vote_count() == 5

    def test_store_vote_returns_id(self, db, chain):
        entry = chain.append(b"vote:candidate_1")
        vote_id = db.store_vote(b"encrypted", entry)
        assert isinstance(vote_id, int)
        assert vote_id >= 1

    def test_vote_ids_increment(self, db, chain):
        ids = []
        for i in range(3):
            entry = chain.append(f"vote:{i}".encode())
            ids.append(db.store_vote(f"enc_{i}".encode(), entry))
        assert ids == sorted(ids)
        assert len(set(ids)) == 3


# ---------------------------------------------------------------------------
# Audit chain tests
# ---------------------------------------------------------------------------

class TestAuditChain:

    def test_load_empty_chain(self, db):
        assert db.load_audit_chain() == []

    def test_stored_chain_entries_match(self, db, chain):
        entries = []
        for i in range(5):
            entry = chain.append(f"vote:{i}".encode())
            db.store_vote(f"enc_{i}".encode(), entry)
            entries.append(entry)

        loaded = db.load_audit_chain()
        assert len(loaded) == 5
        for original, loaded_entry in zip(entries, loaded):
            assert original.sequence  == loaded_entry.sequence
            assert original.timestamp == loaded_entry.timestamp
            assert original.data      == loaded_entry.data
            assert original.hmac      == loaded_entry.hmac

    def test_loaded_chain_verifies(self, db, chain):
        for i in range(5):
            entry = chain.append(f"vote:{i}".encode())
            db.store_vote(f"enc_{i}".encode(), entry)

        loaded = db.load_audit_chain()
        assert chain.verify(loaded) is True

    def test_chain_length_matches_votes(self, db, chain):
        for i in range(7):
            entry = chain.append(f"vote:{i}".encode())
            db.store_vote(f"enc_{i}".encode(), entry)
        assert db.get_audit_chain_length() == db.get_vote_count() == 7