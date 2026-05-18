"""
tests/test_zkp/test_gq.py

Unit tests for crypto/zkp/gq.py

Note: GQ requires RSA key generation — session-scoped fixture
generates the keypair once for all tests.

Run with:
    python -m pytest tests/test_zkp/test_gq.py -v
"""

import pytest
from crypto.zkp.gq import GQZKP, GQProver, GQVerifier, E
from crypto.zkp.base import run_zkp_protocol


@pytest.fixture(scope="module")
def scheme():
    # Use 512-bit keys for test speed — 2048-bit tested in integration
    return GQZKP(bits=512)


@pytest.fixture(scope="module")
def prover_verifier(scheme):
    return scheme.generate_params()


# ---------------------------------------------------------------------------
# Parameter tests
# ---------------------------------------------------------------------------

class TestGQParameters:

    def test_public_exponent_is_65537(self):
        assert E == 65537

    def test_y_computed_correctly(self, prover_verifier):
        prover, _ = prover_verifier
        assert pow(prover._x, prover._e, prover._n) == prover._y

    def test_y_in_valid_range(self, prover_verifier):
        prover, _ = prover_verifier
        assert 1 < prover._y < prover._n

    def test_different_sessions_different_params(self, scheme):
        p1, _ = scheme.generate_params()
        p2, _ = scheme.generate_params()
        # Different RSA keypairs → different moduli
        assert p1._n != p2._n


# ---------------------------------------------------------------------------
# Protocol tests
# ---------------------------------------------------------------------------

class TestGQProtocol:

    def test_commitment_is_integer(self, prover_verifier):
        prover, _ = prover_verifier
        t = prover.commit()
        assert isinstance(t, int)

    def test_commitment_in_range(self, prover_verifier):
        prover, _ = prover_verifier
        t = prover.commit()
        assert 1 <= t < prover._n

    def test_challenge_in_range(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        assert 0 <= c < E

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
        for _ in range(5):
            prover, verifier = scheme.generate_params()
            t = prover.commit()
            c = verifier.challenge(t)
            s = prover.respond(c)
            assert verifier.verify(t, c, s) is True

    def test_respond_without_commit_raises(self, scheme):
        prover, _ = scheme.generate_params()
        with pytest.raises(RuntimeError, match="commit()"):
            prover.respond(1)

    def test_wrong_response_fails(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        assert verifier.verify(t, c, (s + 1) % prover._n) is False

    def test_wrong_commitment_fails(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        assert verifier.verify((t + 1) % prover._n, c, s) is False

    def test_wrong_challenge_fails(self, prover_verifier):
        prover, verifier = prover_verifier
        t = prover.commit()
        c = verifier.challenge(t)
        s = prover.respond(c)
        wrong_c = (c + 1) % E
        assert verifier.verify(t, wrong_c, s) is False

    def test_different_commitments_per_round(self, scheme):
        """Each commit() must produce a fresh random commitment."""
        prover, _ = scheme.generate_params()
        commitments = {prover.commit() for _ in range(10)}
        assert len(commitments) == 10

    def test_run_zkp_protocol_single_round(self, scheme):
        prover, verifier = scheme.generate_params()
        assert run_zkp_protocol(prover, verifier, rounds=1) is True

    def test_dishonest_prover_fails(self, scheme):
        """
        A prover with wrong secret x' cannot satisfy s^e == t * y^c (mod n)
        for a random challenge c.
        """
        import secrets as sec
        prover, verifier = scheme.generate_params()
        n = prover._n

        # Replace prover's secret with a wrong value
        x_wrong = sec.randbelow(n - 2) + 2
        while x_wrong == prover._x:
            x_wrong = sec.randbelow(n - 2) + 2

        dishonest = GQProver(n=n, e=E, x=x_wrong, y=prover._y)

        failures = 0
        for _ in range(10):
            t = dishonest.commit()
            c = verifier.challenge(t)
            s = dishonest.respond(c)
            if not verifier.verify(t, c, s):
                failures += 1

        assert failures > 0, "Dishonest prover should fail at least once"

    def test_verify_handles_bad_input_gracefully(self, prover_verifier):
        _, verifier = prover_verifier
        assert verifier.verify(0, 0, 0) is False


# ---------------------------------------------------------------------------
# Scheme metadata tests
# ---------------------------------------------------------------------------

class TestSchemeMetadata:

    def test_name(self, scheme):
        assert "Guillou" in scheme.name or "GQ" in scheme.name

    def test_hardness_assumption(self, scheme):
        assert "RSA" in scheme.hardness_assumption

    def test_rounds_is_one(self, scheme):
        assert scheme.ROUNDS == 1