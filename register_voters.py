"""
register_voters.py

Pre-election voter registration script.

Run this ONCE before starting the server to populate the voter registry.
Each voter gets an RSA keypair generated here. The private key is printed
to stdout and must be securely distributed to the voter (in a real system,
this would be done via a secure out-of-band channel).

Usage:
    python register_voters.py

This will:
  1. Initialize the database schema
  2. Generate RSA-2048 keypairs for each voter
  3. Store voter records (with public keys) in the DB
  4. Print each voter's private key — distribute securely

WARNING: Running this script again on an existing DB will skip already-
registered voters and only add new ones.
"""

import json
import sys
from db import Database
from crypto.rsa import generate_keypair

DB_PATH = "voting.db"

# ---------------------------------------------------------------------------
# Voter list — edit this before running for each election
# ---------------------------------------------------------------------------

VOTERS = [
    {"voter_id": "V001", "name": "Aarav Sharma",   "constituency": "North Delhi"},
    {"voter_id": "V002", "name": "Priya Nair",     "constituency": "South Mumbai"},
    {"voter_id": "V003", "name": "Rohan Verma",    "constituency": "East Bangalore"},
    {"voter_id": "V004", "name": "Sneha Pillai",   "constituency": "West Chennai"},
    {"voter_id": "V005", "name": "Arjun Mehta",    "constituency": "Central Hyderabad"},
]


def main() -> None:
    db = Database(DB_PATH)
    db.init_schema()

    print("=" * 60)
    print("  VOTER REGISTRATION — CRYPTOGRAPHIC VOTING SYSTEM")
    print("=" * 60)
    print(f"  Database: {DB_PATH}")
    print(f"  Registering {len(VOTERS)} voter(s)...\n")

    registered = 0
    skipped    = 0

    for voter in VOTERS:
        voter_id     = voter["voter_id"]
        name         = voter["name"]
        constituency = voter["constituency"]

        if db.voter_exists(voter_id):
            print(f"  [SKIP] {voter_id} ({name}) — already registered.")
            skipped += 1
            continue

        print(f"  Generating RSA-2048 keypair for {name}...", end=" ", flush=True)
        pub, priv = generate_keypair(bits=2048)
        print("done.")

        db.register_voter(
            voter_id=voter_id,
            name=name,
            constituency=constituency,
            n=pub.n,
            e=pub.e,
        )

        # Print private key — in a real system this is distributed securely
        print(f"\n  ── Voter: {name} ({voter_id}) ──────────────────────────")
        print(f"  Constituency : {constituency}")
        print(f"  RSA n        : {str(pub.n)[:40]}...  ({pub.n.bit_length()} bits)")
        print(f"  RSA e        : {pub.e}")
        print(f"  RSA d (PRIVATE KEY — distribute securely):")
        print(f"  {str(priv.d)[:80]}...")
        print(f"  RSA p        : {str(priv.p)[:40]}...")
        print(f"  RSA q        : {str(priv.q)[:40]}...")

        # Save private key to a file named after voter_id
        key_file = f"{voter_id}_private_key.json"
        with open(key_file, "w") as f:
            json.dump({
                "voter_id": voter_id,
                "name": name,
                "n": str(pub.n),
                "e": pub.e,
                "d": str(priv.d),
                "p": str(priv.p),
                "q": str(priv.q),
            }, f, indent=2)
        print(f"  Private key saved to: {key_file}\n")
        registered += 1

    print("=" * 60)
    print(f"  Registration complete.")
    print(f"  Registered : {registered}")
    print(f"  Skipped    : {skipped}")
    print("=" * 60)
    print("\n  IMPORTANT: Distribute each voter's private key file")
    print("  securely before the election begins.\n")


if __name__ == "__main__":
    main()