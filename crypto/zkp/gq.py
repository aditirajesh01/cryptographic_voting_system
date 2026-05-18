"""
crypto/zkp/gq.py

Guillou-Quisquater (GQ) Protocol — Zero-Knowledge Proof of RSA witness.

Hardness assumption: RSA assumption.
Given n = p*q (RSA modulus), public exponent e, and y = x^e mod n,
finding x without knowing the factorization of n is computationally
infeasible — this is exactly the RSA problem.

This scheme reuses the RSA infrastructure already present in crypto/rsa.py
(same modulus size, same public exponent e = 65537). The architectural
coherence makes GQ a natural third comparison point alongside Graph
Isomorphism (combinatorial hardness) and Schnorr (discrete log).

Protocol (Guillou & Quisquater 1988):
    Public:  n (RSA modulus), e (public exponent), y = x^e mod n
    Witness: x (e-th root of y mod n — the secret)

    1. Prover picks random r ∈ [1, n-1], computes t = r^e mod n
    2. Prover sends commitment t to Verifier
    3. Verifier sends challenge c ∈ [0, e)
    4. Prover computes response s = r * x^c mod n
    5. Verifier checks: s^e mod n == (t * y^c) mod n

    Soundness: Knowledge extractor can recover x from two transcripts
    with the same t but different c, d where gcd(c-d, e) = 1 — reducing
    to the RSA problem.

    Zero-knowledge: r is uniformly random in Z*_n, so t = r^e is
    uniformly distributed. The verifier learns nothing about x.

Key generation: We generate a fresh RSA-2048 keypair. The prover's
secret x is a random element of Z*_n; the public value is y = x^e mod n.

Usage:
    from crypto.zkp.gq import GQZKP
    from crypto.zkp.base import run_zkp_protocol

    scheme = GQZKP()
    prover, verifier = scheme.generate_params()
    accepted = run_zkp_protocol(prover, verifier, rounds=1)
"""

import secrets
from crypto.zkp.base import ZKPProver, ZKPVerifier, ZKPScheme
from crypto.rsa import generate_keypair, RSAPublicKey, RSAPrivateKey

# Public exponent — same as RSA module
E = 65537


# ---------------------------------------------------------------------------
# Prover
# ---------------------------------------------------------------------------

class GQProver(ZKPProver):
    """
    GQ prover — knows x such that y = x^e mod n.
    """

    def __init__(self, n: int, e: int, x: int, y: int):
        """
        Args:
            n: RSA modulus.
            e: Public exponent.
            x: Secret witness (e-th root of y mod n).
            y: Public value y = x^e mod n.
        """
        self._n = n
        self._e = e
        self._x = x
        self._y = y
        self._r: int | None = None  # Per-round nonce

    def setup(self) -> dict:
        return {"n": self._n, "e": self._e, "y": self._y}

    def commit(self) -> int:
        """
        Pick random r ∈ [1, n-1], compute commitment t = r^e mod n.

        Returns:
            t — commitment integer.
        """
        # Generate r in [1, n-1]
        while True:
            self._r = secrets.randbelow(self._n - 1) + 1
            if self._r > 1:
                break
        return pow(self._r, self._e, self._n)

    def respond(self, challenge: int) -> int:
        """
        Compute response s = r * x^c mod n.

        Args:
            challenge: Integer c from the verifier, in [0, e).

        Returns:
            Response integer s.
        """
        if self._r is None:
            raise RuntimeError("commit() must be called before respond().")
        return (self._r * pow(self._x, challenge, self._n)) % self._n


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class GQVerifier(ZKPVerifier):
    """
    GQ verifier — checks s^e == t * y^c (mod n).
    """

    def __init__(self, n: int, e: int, y: int):
        """
        Args:
            n: RSA modulus.
            e: Public exponent.
            y: Public value y = x^e mod n.
        """
        self._n = n
        self._e = e
        self._y = y

    def challenge(self, commitment: int) -> int:
        """
        Send a random challenge c ∈ [0, e).

        Args:
            commitment: The prover's commitment t.

        Returns:
            Random challenge c.
        """
        return secrets.randbelow(self._e)

    def verify(self, commitment: int, challenge: int, response: int) -> bool:
        """
        Verify: s^e mod n == (t * y^c) mod n

        Args:
            commitment: t — prover's commitment.
            challenge:  c — verifier's challenge.
            response:   s — prover's response.

        Returns:
            True if verification passes.
        """
        try:
            # Reject trivial inputs
            if response <= 0 or commitment <= 0:
                return False
            lhs = pow(response, self._e, self._n)
            rhs = (commitment * pow(self._y, challenge, self._n)) % self._n
            return lhs == rhs
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Scheme factory
# ---------------------------------------------------------------------------

class GQZKP(ZKPScheme):
    """
    Guillou-Quisquater ZKP scheme factory.

    Generates an RSA-2048 keypair, picks random x ∈ Z*_n,
    computes y = x^e mod n, and returns configured prover/verifier.
    """

    # GQ is a single-round proof — soundness from RSA assumption.
    ROUNDS = 1

    def __init__(self, bits: int = 2048):
        """
        Args:
            bits: RSA modulus size. Default 2048.
                  Use smaller values (e.g. 512) only for testing.
        """
        self._bits = bits

    @property
    def name(self) -> str:
        return "Guillou-Quisquater (GQ) Protocol"

    @property
    def hardness_assumption(self) -> str:
        return "RSA assumption (integer factorization)"

    def generate_params(self) -> tuple[GQProver, GQVerifier]:
        """
        Generate RSA modulus n, pick secret x, compute y = x^e mod n.

        Returns:
            (GQProver, GQVerifier)
        """
        pub, _ = generate_keypair(bits=self._bits)
        n = pub.n
        e = pub.e  # Always 65537

        # Pick random x ∈ [2, n-2] as the secret witness
        while True:
            x = secrets.randbelow(n - 2) + 2
            if x > 1:
                break

        y = pow(x, e, n)

        prover   = GQProver(n=n, e=e, x=x, y=y)
        verifier = GQVerifier(n=n, e=e, y=y)
        return prover, verifier