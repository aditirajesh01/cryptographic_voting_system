"""
audit_verify.py

Standalone audit verification script for the cryptographic voting system.

Loads the HMAC audit chain from the database, recomputes every entry's
HMAC from scratch, and verifies the chain is intact. Any modification,
deletion, or insertion of records will be detected.

The chain key must be available in chain_key.bin (written by server.py
at startup). Without the key, HMAC verification is impossible.

Usage:
    python audit_verify.py [--db DB_PATH] [--key CHAIN_KEY_PATH]

Defaults:
    db:  voting.db
    key: chain_key.bin

Exit codes:
    0 — chain verified, no tampering detected
    1 — chain verification failed or error occurred
"""

import argparse
import sys
from db import Database
from crypto.hmac_chain import HMACChain

DEFAULT_DB      = "voting.db"
DEFAULT_KEY     = "chain_key.bin"


def load_chain_key(key_path: str) -> bytes:
    """
    Load the HMAC chain key from disk.

    Raises:
        SystemExit: If the key file is missing or wrong length.
    """
    try:
        with open(key_path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            print(f"[!] Invalid chain key length: {len(key)} bytes (expected 32).")
            sys.exit(1)
        return key
    except FileNotFoundError:
        print(f"[!] Chain key file not found: {key_path}")
        print("    The server must have been run at least once to generate this file.")
        sys.exit(1)


def run_audit(db_path: str, key_path: str) -> bool:
    """
    Load chain from DB and verify integrity.

    Returns:
        True if chain is valid, False if tampering detected.
    """
    print("=" * 60)
    print("  CRYPTOGRAPHIC VOTING SYSTEM — AUDIT VERIFICATION")
    print("=" * 60)
    print(f"  Database  : {db_path}")
    print(f"  Chain key : {key_path}\n")

    # Load chain key
    chain_key = load_chain_key(key_path)
    chain     = HMACChain(chain_key)

    # Load DB
    db = Database(db_path)

    # Load audit chain entries
    print("[*] Loading audit chain from database...", end=" ", flush=True)
    entries = db.load_audit_chain()
    print(f"{len(entries)} entries loaded.")

    vote_count = db.get_vote_count()
    print(f"[*] Total votes in database: {vote_count}")

    if len(entries) != vote_count:
        print(f"\n[!] MISMATCH: audit chain has {len(entries)} entries "
              f"but votes table has {vote_count} records.")
        print("    This indicates tampering or data corruption.")
        return False

    if len(entries) == 0:
        print("\n[*] No votes cast. Audit trivially passes.")
        print("\n" + "=" * 60)
        print("  AUDIT RESULT: PASS (empty election)")
        print("=" * 60)
        return True

    # Verify chain
    print("[*] Verifying HMAC chain integrity...", end=" ", flush=True)
    valid = chain.verify(entries)

    if valid:
        print("PASS.\n")
        print("=" * 60)
        print("  AUDIT RESULT: PASS")
        print(f"  {len(entries)} votes verified. Chain is intact.")
        print("  No tampering detected.")
        print("=" * 60)
        return True
    else:
        print("FAIL.\n")
        print("=" * 60)
        print("  AUDIT RESULT: FAIL")
        print("  HMAC chain verification failed.")
        print("  The audit log has been tampered with or corrupted.")
        print("=" * 60)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cryptographic Voting System — Audit Verification"
    )
    parser.add_argument("--db",  default=DEFAULT_DB,  help="Path to SQLite database")
    parser.add_argument("--key", default=DEFAULT_KEY, help="Path to chain key file")
    args = parser.parse_args()

    success = run_audit(db_path=args.db, key_path=args.key)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()