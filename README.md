# Cryptographic Voting System

A cryptographically secure electronic voting system implemented from scratch in Python 3.14. Built as a working implementation and research artifact for an empirical comparison of Zero-Knowledge Proof schemes.

**Research context:** Motivated by Wolchok et al. (2010 CCS) — India's EVMs lack cryptographic verifiability, requiring pure institutional trust. This system replaces trust with mathematical proof.

---

## Cryptographic Stack

| Layer | Primitive | Purpose |
|---|---|---|
| Transport | Diffie-Hellman (RFC 3526 Group 14, 2048-bit) | Session key establishment |
| Encryption | AES-256-CBC (from scratch) | All messages in transit |
| Authentication | RSA-2048 challenge-response (from scratch) | Voter identity verification |
| Anonymity | Zero-Knowledge Proof — Graph Isomorphism | Proves eligibility without linking identity to vote |
| Replay prevention | HMAC-based one-time tokens | Prevents vote replay attacks |
| Audit | HMAC-SHA256 chain | Tamper-evident vote log |

All cryptographic primitives are implemented from scratch. No `cryptography`, `pycryptodome`, or equivalent libraries are used.

---

## Project Structure

```
cryptographic_voting_system/
├── crypto/
│   ├── dh.py               # DH key exchange + HKDF-SHA256
│   ├── aes.py              # AES-256-CBC from scratch (FIPS 197)
│   ├── rsa.py              # RSA-2048 from scratch (Miller-Rabin)
│   ├── hmac_chain.py       # Tamper-evident HMAC audit chain
│   ├── tokens.py           # Anti-replay token manager
│   └── zkp/
│       ├── base.py         # Abstract ZKP interface
│       ├── graph_iso.py    # Graph Isomorphism ZKP (live system)
│       ├── schnorr.py      # Schnorr Sigma Protocol (benchmark)
│       ├── gq.py           # Guillou-Quisquater Protocol (benchmark)
│       └── benchmark.py    # Empirical ZKP comparison
├── tests/                  # Unit tests for all crypto modules
├── server.py               # Threaded TCP voting server
├── voter_cli.py            # Voter terminal client
├── register_voters.py      # Pre-election voter registration
├── audit_verify.py         # Standalone audit verification
├── db.py                   # SQLite data access layer
└── candidates.json         # Election candidate configuration
```

---

## Requirements

- Python 3.12+
- pytest (for running tests)

```bash
pip install pytest
```

No other dependencies required.

---

## Running the System

### Step 1 — Configure candidates

Edit `candidates.json` to define the election candidates:

```json
{
    "candidates": [
        {"id": "C1", "name": "Candidate A", "party": "Party A"},
        {"id": "C2", "name": "Candidate B", "party": "Party B"},
        {"id": "C3", "name": "Candidate C", "party": "Party C"}
    ]
}
```

### Step 2 — Register voters

Run once before the election. Generates RSA-2048 keypairs for each voter and populates the database. Edit the `VOTERS` list in `register_voters.py` before running.

```bash
python register_voters.py
```

This generates a private key file for each voter (e.g. `V001_private_key.json`). Distribute each file securely to the corresponding voter before the election begins.

### Step 3 — Start the server

```bash
python server.py
```

Optional arguments:
```
--host HOST    Bind address (default: 127.0.0.1)
--port PORT    Port number (default: 65432)
--db   PATH    SQLite database path (default: voting.db)
```

### Step 4 — Vote (separate terminal per voter)

```bash
python voter_cli.py --key V001_private_key.json
```

The client will:
1. Perform DH key exchange with the server
2. Authenticate via RSA challenge-response
3. Complete a 40-round Zero-Knowledge Proof
4. Display the ballot and accept the voter's choice
5. Confirm the vote was recorded

### Step 5 — Verify the audit log

After the election, run the standalone audit script:

```bash
python audit_verify.py
```

This recomputes the entire HMAC chain from scratch and verifies no votes were added, removed, or modified. Requires `chain_key.bin` (written by the server at startup).

---

## Protocol Flow

```
Voter (Client)                          Server
──────────────────────────────────────────────────────────────
TCP connect ──────────────────────────►
◄──────────────────────── DH public key
DH public key ────────────────────────►
         [Both derive AES session key via HKDF-SHA256]

voter_id (encrypted) ─────────────────►
◄──────────────── identity OK / rejected

◄──────────── RSA challenge (encrypted with voter's public key)
RSA response (decrypted with private key) ──────────────────►
◄────────────────────────────── auth OK

         [40-round Graph Isomorphism ZKP]
         Prover (client) ←→ Verifier (server)
◄─────────────────────────── ZKP passed

◄──────────── anti-replay token + candidate list
vote + token ─────────────────────────►
◄────────────────────────── vote accepted

TCP close ────────────────────────────►
```

---

## Running Tests

```bash
# All tests
python -m pytest --tb=short -q

# Individual modules
python -m pytest tests/test_dh.py -v
python -m pytest tests/test_aes.py -v
python -m pytest tests/test_rsa.py -v
python -m pytest tests/test_hmac_chain.py -v
python -m pytest tests/test_tokens.py -v
python -m pytest tests/test_db.py -v
python -m pytest tests/test_zkp/ -v
```

AES tests verify against NIST FIPS 197 known-answer vectors. DH tests verify against RFC 5869 HKDF test vectors.

---

## ZKP Benchmark

Empirically compares three ZKP schemes across distinct hardness assumptions:

| Scheme | Hardness Assumption | Full Protocol (ms) | Proof Size |
|---|---|---|---|
| Graph Isomorphism | Combinatorial (GI) | 2.17 | 774 bytes |
| Schnorr Sigma | Discrete Logarithm | 76.55 | 512 bytes |
| Guillou-Quisquater | RSA assumption | 1038.85 | 512 bytes |

Run the benchmark:

```bash
# Quick run (5 iterations)
python -m crypto.zkp.benchmark --iterations 5 --rounds 40

# Full run for paper-quality data (50 iterations, ~15 min)
python -m crypto.zkp.benchmark --iterations 50 --rounds 40 --output benchmark_results.json
```

Results are saved to `benchmark_results.json`.

---

## Security Properties

**Voter anonymity:** The Graph Isomorphism ZKP proves a voter is eligible without revealing which voter cast which vote. Voter identity is never stored alongside vote choices.

**Tamper evidence:** Every vote extends an HMAC chain. Any modification, insertion, or deletion of records invalidates all subsequent HMACs — detectable by `audit_verify.py` without decrypting individual votes.

**Replay prevention:** Each session token is consumed on use. Replaying an intercepted encrypted message is rejected by the server regardless of whether the attacker can break the encryption.

**No trusted third party:** The system requires no PKI, certificate authority, or trusted intermediary. Security guarantees are derived entirely from cryptographic hardness assumptions.

---

## Research Paper

**Title:** Empirical Comparison of Zero-Knowledge Proof Schemes in a Cryptographically Secure Electronic Voting System

**Target venues:** IEEE Access, Computers & Security

**Key contribution:** Empirical evaluation of Graph Isomorphism ZKP against Schnorr (DLP) and Guillou-Quisquater (RSA) in a working voting system, demonstrating that combinatorial-hardness ZKP achieves sub-millisecond per-round performance without dependence on number-theoretic assumptions.

**Motivation:** Wolchok, S., Wustrow, E., Halderman, J.A., et al. (2010). *Security Analysis of India's Electronic Voting Machines*. ACM CCS 2010.

---

## Authors

Aditi Rajesh — 6th Semester, Computer Science Engineering
NPS Lab Project