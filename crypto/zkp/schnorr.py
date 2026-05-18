"""
crypto/zkp/schnorr.py

Schnorr Sigma Protocol — Zero-Knowledge Proof of discrete logarithm.

Hardness assumption: Discrete Logarithm Problem (DLP).
Given a prime p, generator g, and y = g^x mod p, finding x is
computationally infeasible for large p (no known sub-exponential
algorithm for general DLP over prime-order groups).

Protocol (Schnorr 1991):
    Public:  p (safe prime), g (generator), y = g^x mod p
    Witness: x (discrete logarithm — the secret)

    1. Prover picks random r ∈ [1, q-1], computes t = g^r mod p
    2. Prover sends commitment t to Verifier
    3. Verifier sends challenge c ∈ [0, 2^128) (random integer)
    4. Prover computes response s = (r + c*x) mod q
    5. Verifier checks: g^s mod p == (t * y^c) mod p

    Soundness: Extracting x from two valid transcripts with the same t
    but different c requires solving DLP — computationally infeasible.

    Zero-knowledge: The response s is uniformly distributed mod q
    regardless of x, so the verifier learns nothing about x.

    Unlike graph isomorphism, Schnorr is a single-round proof (the
    soundness guarantee comes from the algebraic structure, not
    repetition). However, we run it for ROUNDS iterations in the
    benchmark to measure per-round cost comparably.

Group parameters: We use RFC 3526 Group 14 (2048-bit safe prime p).
    q = (p-1)/2 is the prime-order subgroup size.
    g = 2 is a generator of the subgroup of order q.

Usage:
    from crypto.zkp.schnorr import SchnorrZKP
    from crypto.zkp.base import run_zkp_protocol

    scheme = SchnorrZKP()
    prover, verifier = scheme.generate_params()
    accepted = run_zkp_protocol(prover, verifier, rounds=1)
"""

import secrets
from crypto.zkp.base import ZKPProver, ZKPVerifier, ZKPScheme

# ---------------------------------------------------------------------------
# RFC 3526 Group 14 — 2048-bit safe prime
# Same group as crypto/dh.py — reuses existing infrastructure
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
Q = (P - 1) // 2  # Prime-order subgroup size (P is a safe prime, so Q is prime)

# Challenge bit length — 128-bit challenge for 128-bit soundness
CHALLENGE_BITS = 128


# ---------------------------------------------------------------------------
# Prover
# ---------------------------------------------------------------------------

class SchnorrProver(ZKPProver):
    """
    Schnorr prover — knows secret x such that y = g^x mod p.
    """

    def __init__(self, x: int, y: int):
        """
        Args:
            x: Secret discrete logarithm (witness).
            y: Public value y = g^x mod p.
        """
        self._x = x
        self._y = y
        self._r: int | None = None  # Per-round nonce

    def setup(self) -> dict:
        return {"p": P, "g": G, "q": Q, "y": self._y}

    def commit(self) -> int:
        """
        Pick random nonce r, compute commitment t = g^r mod p.

        Returns:
            t — the commitment integer.
        """
        self._r = secrets.randbelow(Q - 1) + 1  # r ∈ [1, Q-1]
        return pow(G, self._r, P)

    def respond(self, challenge: int) -> int:
        """
        Compute response s = (r + c * x) mod q.

        Args:
            challenge: Integer c from the verifier.

        Returns:
            Response integer s.
        """
        if self._r is None:
            raise RuntimeError("commit() must be called before respond().")
        return (self._r + challenge * self._x) % Q


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class SchnorrVerifier(ZKPVerifier):
    """
    Schnorr verifier — checks g^s == t * y^c (mod p).
    """

    def __init__(self, y: int):
        """
        Args:
            y: Public value y = g^x mod p.
        """
        self._y = y
        self._last_commitment: int | None = None

    def challenge(self, commitment: int) -> int:
        """
        Send a random 128-bit challenge integer.

        Args:
            commitment: The prover's commitment t (stored for verify).

        Returns:
            Random challenge c.
        """
        self._last_commitment = commitment
        return secrets.randbelow(2 ** CHALLENGE_BITS)

    def verify(self, commitment: int, challenge: int, response: int) -> bool:
        """
        Verify: g^s mod p == (t * y^c) mod p

        Args:
            commitment: t — prover's commitment.
            challenge:  c — verifier's challenge.
            response:   s — prover's response.

        Returns:
            True if verification passes.
        """
        try:
            lhs = pow(G, response, P)
            rhs = (commitment * pow(self._y, challenge, P)) % P
            return lhs == rhs
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Scheme factory
# ---------------------------------------------------------------------------

class SchnorrZKP(ZKPScheme):
    """
    Schnorr Sigma Protocol scheme factory.

    Generates a random secret x, computes y = g^x mod p,
    and returns configured prover/verifier instances.
    """

    # Schnorr is a single-round proof — soundness from DLP, not repetition.
    # ROUNDS=1 for correctness; benchmark runs it multiple times for timing.
    ROUNDS = 1

    @property
    def name(self) -> str:
        return "Schnorr Sigma Protocol"

    @property
    def hardness_assumption(self) -> str:
        return "Discrete Logarithm Problem (DLP)"

    def generate_params(self) -> tuple[SchnorrProver, SchnorrVerifier]:
        """
        Generate secret x ∈ [1, q-1], public y = g^x mod p.

        Returns:
            (SchnorrProver, SchnorrVerifier)
        """
        x = secrets.randbelow(Q - 1) + 1  # x ∈ [1, Q-1]
        y = pow(G, x, P)

        prover   = SchnorrProver(x=x, y=y)
        verifier = SchnorrVerifier(y=y)
        return prover, verifier