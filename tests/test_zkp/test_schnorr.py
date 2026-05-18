"""
tests/test_zkp/test_schnorr.py

Unit tests for crypto/zkp/schnorr.py

Run with:
    python -m pytest tests/test_zkp/test_schnorr.py -v
"""

import pytest
from crypto.zkp.schnorr import (
    SchnorrZKP,
    SchnorrProver,
    SchnorrVerifier,
    P, G, Q,
)
from crypto.zkp.base import run_zkp_protocol


@pytest.fixture(scope="module")
def scheme():
    return SchnorrZKP()


@pytest.fixture(scope="module")
def prover_verifier(scheme):
    return scheme.generate_params()


# ---------------------------------------------------------------------------
# Parameter tests
# ---------------------------------------------------------------------------

class TestGroupParameters:

    def test_p_is_large(self):
        assert P.bit_length() == 2048

    def test_q_is_half_p_minus_1(self):
        assert Q == (P - 1) // 2

    def test_g_is_two(self):
        assert G == 2

    def test_g_in_subgroup(self):
        """g^q mod p must equal 1 — confirms g generates the subgroup of order q."""
        assert pow(G, Q, P) == 1


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------

class TestKeyGeneration:

    def test_generates_valid_y(self, scheme):
        prover, verifier = scheme.generate_params()
        params = prover.setup()
        assert 2 <= params["y"] <= P - 2

    def test_different_sessions_have_different_secrets(self, scheme):
        p1, _ = scheme.generate_params()
        p2, _ = scheme.generate_params()
        assert p1._x != p2._x

    def test_y_equals_g_to_the_x(self, scheme):
        prover, _ = scheme.generate_params()
        assert pow(G, prover._x, P) == prover._y


# ---------------------------------------------------------------------------
# Protocol tests
# ---------------------------------------------------------------------------

class TestSchnorrProtocol:

    def test_commitment_is_integer(self, prover_verifier):
        prover, _ = prover_verifier
        t = prover.commit()
        assert isinstance(t, int)

    def test_commitment_in_range(self, prover_verifier):
        prover, _ = prover_verifier
        t = prover.commit()
        assert 1 <= t <= P - 1

    def test_challenge_is_integer(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        assert isinstance(c, int)

    def test_challenge_is_positive(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        assert c >= 0

    def test_response_is_integer(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        assert isinstance(s, int)

    def test_honest_prover_verifies(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        assert verifier.verify(t, c, s) is True

    def test_honest_prover_verifies_multiple_rounds(self, scheme):
        for _ in range(10):
            prover, verifier = scheme.generate_params()
            t = prover.commit()
            c = verifier.challenge(t)
            s = prover.respond(c)
            assert verifier.verify(t, c, s) is True

    def test_respond_without_commit_raises(self, scheme):
        prover, _ = scheme.generate_params()
        with pytest.raises(RuntimeError, match="commit()"):
            prover.respond(42)

    def test_wrong_response_fails(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        wrong_s = prover.respond(c) + 1
        assert verifier.verify(t, c, wrong_s) is False

    def test_wrong_commitment_fails(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        assert verifier.verify(t + 1, c, s) is False

    def test_wrong_challenge_fails(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        assert verifier.verify(t, c + 1, s) is False

    def test_different_commitments_per_round(self, scheme):
        """Each commit() must produce a fresh random commitment."""
        prover, _ = scheme.generate_params()
        commitments = {prover.commit() for _ in range(20)}
        assert len(commitments) == 20

    def test_run_zkp_protocol_single_round(self, scheme):
        prover, verifier = scheme.generate_params()
        assert run_zkp_protocol(prover, verifier, rounds=1) is True

    def test_dishonest_prover_fails(self):
        """
        A prover with wrong secret x' != x cannot satisfy the verification
        equation g^s == t * y^c (mod p) for a random challenge c.
        """
        import secrets as sec
        x_real  = sec.randbelow(Q - 1) + 1
        x_wrong = sec.randbelow(Q - 1) + 1
        while x_wrong == x_real:
            x_wrong = sec.randbelow(Q - 1) + 1

        y        = pow(G, x_real, P)
        prover   = SchnorrProver(x=x_wrong, y=y)
        verifier = SchnorrVerifier(y=y)

        failures = 0
        for _ in range(20):
            t = prover.commit()
            c = verifier.challenge(t)
            s = prover.respond(c)
            if not verifier.verify(t, c, s):
                failures += 1

        assert failures > 0, "Dishonest prover should fail at least once in 20 rounds"


# ---------------------------------------------------------------------------
# Scheme metadata tests
# ---------------------------------------------------------------------------

class TestSchemeMetadata:

    def test_name(self, scheme):
        assert "Schnorr" in scheme.name

    def test_hardness_assumption(self, scheme):
        assert "Discrete" in scheme.hardness_assumption

    def test_rounds_is_one(self, scheme):
        assert scheme.ROUNDS == 1