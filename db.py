"""
db.py

SQLite database layer for the cryptographic voting system.

Schema:
    voters      — voter registry (ID, RSA public key, has_voted flag)
    votes       — encrypted vote payloads (no plaintext, no voter linkage)
    audit_chain — HMAC chain entries for tamper-evident audit log

No crypto logic lives here. This module is a pure data access layer.

Usage:
    from db import Database

    db = Database("voting.db")
    db.init_schema()

    db.register_voter("voter_001", n=pub.n, e=pub.e)
    db.store_vote(encrypted_payload, chain_entry)
"""

import sqlite3
import time
from typing import Optional
from crypto.hmac_chain import ChainEntry


class Database:
    """
    SQLite database access layer.

    One instance per server process. All methods open and close their
    own connections to remain compatible with multi-threaded use
    (SQLite connections are not thread-safe by default).

    For in-memory databases (db_path=":memory:"), a single persistent
    connection is used since in-memory databases are per-connection.
    """

    def __init__(self, db_path: str = "voting.db"):
        """
        Args:
            db_path: Path to the SQLite database file.
                     Use ":memory:" for in-process testing.
        """
        self.db_path = db_path
        self._memory_conn: sqlite3.Connection | None = None

        if db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys=ON")

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # Better concurrency
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        """
        Create all tables if they do not exist.
        Safe to call multiple times (idempotent).
        """
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS voters (
                    voter_id    TEXT    PRIMARY KEY,
                    rsa_n       TEXT    NOT NULL,
                    rsa_e       TEXT    NOT NULL,
                    has_voted   INTEGER NOT NULL DEFAULT 0,
                    registered_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS votes (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_vote  BLOB    NOT NULL,
                    cast_at         INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_chain (
                    sequence    INTEGER PRIMARY KEY,
                    timestamp   INTEGER NOT NULL,
                    data        BLOB    NOT NULL,
                    hmac        BLOB    NOT NULL
                );
            """)

    # ------------------------------------------------------------------
    # Voter registry
    # ------------------------------------------------------------------

    def register_voter(self, voter_id: str, n: int, e: int) -> None:
        """
        Register a voter with their RSA public key.

        Args:
            voter_id: Unique voter identifier (e.g. national ID hash).
            n: RSA modulus as integer.
            e: RSA public exponent as integer.

        Raises:
            ValueError: If voter_id is already registered.
        """
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT voter_id FROM voters WHERE voter_id = ?", (voter_id,)
            ).fetchone()
            if existing:
                raise ValueError(f"Voter '{voter_id}' is already registered.")
            conn.execute(
                "INSERT INTO voters (voter_id, rsa_n, rsa_e, has_voted, registered_at) "
                "VALUES (?, ?, ?, 0, ?)",
                (voter_id, str(n), str(e), int(time.time())),
            )

    def get_voter(self, voter_id: str) -> Optional[dict]:
        """
        Retrieve voter record by ID.

        Returns:
            Dict with keys: voter_id, rsa_n (int), rsa_e (int), has_voted (bool).
            None if voter not found.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT voter_id, rsa_n, rsa_e, has_voted FROM voters WHERE voter_id = ?",
                (voter_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "voter_id": row["voter_id"],
                "rsa_n":    int(row["rsa_n"]),
                "rsa_e":    int(row["rsa_e"]),
                "has_voted": bool(row["has_voted"]),
            }

    def mark_voted(self, voter_id: str) -> None:
        """
        Mark a voter as having cast their vote.

        Args:
            voter_id: Voter to mark.

        Raises:
            ValueError: If voter not found or has already voted.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT has_voted FROM voters WHERE voter_id = ?", (voter_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Voter '{voter_id}' not found.")
            if row["has_voted"]:
                raise ValueError(f"Voter '{voter_id}' has already voted.")
            conn.execute(
                "UPDATE voters SET has_voted = 1 WHERE voter_id = ?", (voter_id,)
            )

    def has_voted(self, voter_id: str) -> bool:
        """
        Check if a voter has already cast their vote.

        Returns:
            True if voted, False if not. False if voter not found.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT has_voted FROM voters WHERE voter_id = ?", (voter_id,)
            ).fetchone()
            if row is None:
                return False
            return bool(row["has_voted"])

    def voter_exists(self, voter_id: str) -> bool:
        """Check if a voter ID is registered."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM voters WHERE voter_id = ?", (voter_id,)
            ).fetchone()
            return row is not None

    def get_all_voters(self) -> list[dict]:
        """Return all registered voters (for admin/audit use)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT voter_id, has_voted FROM voters ORDER BY registered_at"
            ).fetchall()
            return [{"voter_id": r["voter_id"], "has_voted": bool(r["has_voted"])} for r in rows]

    # ------------------------------------------------------------------
    # Vote storage
    # ------------------------------------------------------------------

    def store_vote(self, encrypted_vote: bytes, chain_entry: ChainEntry) -> int:
        """
        Store an encrypted vote and its corresponding audit chain entry
        atomically. Both writes succeed or neither does.

        Args:
            encrypted_vote: AES-encrypted vote payload bytes.
            chain_entry:    Corresponding HMACChain entry.

        Returns:
            The auto-incremented vote ID.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO votes (encrypted_vote, cast_at) VALUES (?, ?)",
                (encrypted_vote, chain_entry.timestamp),
            )
            vote_id = cursor.lastrowid

            conn.execute(
                "INSERT INTO audit_chain (sequence, timestamp, data, hmac) "
                "VALUES (?, ?, ?, ?)",
                (
                    chain_entry.sequence,
                    chain_entry.timestamp,
                    chain_entry.data,
                    chain_entry.hmac,
                ),
            )
            return vote_id

    def get_vote_count(self) -> int:
        """Return total number of votes cast."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM votes").fetchone()
            return row["cnt"]

    # ------------------------------------------------------------------
    # Audit chain
    # ------------------------------------------------------------------

    def load_audit_chain(self) -> list[ChainEntry]:
        """
        Load the full audit chain from the database, ordered by sequence.

        Returns:
            List of ChainEntry objects in sequence order.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT sequence, timestamp, data, hmac "
                "FROM audit_chain ORDER BY sequence ASC"
            ).fetchall()
            return [
                ChainEntry(
                    sequence=row["sequence"],
                    timestamp=row["timestamp"],
                    data=bytes(row["data"]),
                    hmac=bytes(row["hmac"]),
                )
                for row in rows
            ]

    def get_audit_chain_length(self) -> int:
        """Return the number of entries in the audit chain."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_chain"
            ).fetchone()
            return row["cnt"]