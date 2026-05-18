"""
tests/test_zkp/test_graph_iso.py

Unit tests for crypto/zkp/graph_iso.py

Run with:
    python -m pytest tests/test_zkp/test_graph_iso.py -v
"""

import pytest
from crypto.zkp.graph_iso import (
    GraphIsomorphismZKP,
    GraphIsomorphismProver,
    GraphIsomorphismVerifier,
    _apply_permutation,
    _random_permutation,
    _invert_permutation,
    _compose_permutations,
    _generate_random_graph,
)
from crypto.zkp.base import run_zkp_protocol


# ---------------------------------------------------------------------------
# Permutation utility tests
# ---------------------------------------------------------------------------

class TestPermutationUtils:

    def test_random_permutation_length(self):
        p = _random_permutation(10)
        assert len(p) == 10

    def test_random_permutation_is_bijection(self):
        p = _random_permutation(20)
        assert sorted(p) == list(range(20))

    def test_invert_permutation_correctness(self):
        p = _random_permutation(15)
        inv = _invert_permutation(p)
        for i in range(15):
            assert inv[p[i]] == i

    def test_compose_permutations(self):
        # Identity composed with anything is that thing
        n = 10
        identity = list(range(n))
        p = _random_permutation(n)
        assert _compose_permutations(identity, p) == p
        assert _compose_permutations(p, identity) == p

    def test_compose_with_inverse_is_identity(self):
        n = 15
        p = _random_permutation(n)
        inv = _invert_permutation(p)
        result = _compose_permutations(p, inv)
        assert result == list(range(n))

    def test_apply_permutation_preserves_edge_count(self):
        g = _generate_random_graph(10)
        p = _random_permutation(10)
        g2 = _apply_permutation(g, p)
        assert len(g2) == len(g)

    def test_apply_identity_permutation(self):
        g = _generate_random_graph(10)
        identity = list(range(10))
        assert _apply_permutation(g, identity) == g

    def test_apply_then_inverse_returns_original(self):
        g = _generate_random_graph(10)
        p = _random_permutation(10)
        inv = _invert_permutation(p)
        g2 = _apply_permutation(g, p)
        g3 = _apply_permutation(g2, inv)
        assert g3 == g


# ---------------------------------------------------------------------------
# Graph generation tests
# ---------------------------------------------------------------------------

class TestGraphGeneration:

    def test_graph_is_frozenset(self):
        g = _generate_random_graph(10)
        assert isinstance(g, frozenset)

    def test_edges_normalized(self):
        """All edges must have u < v."""
        g = _generate_random_graph(15)
        for u, v in g:
            assert u < v

    def test_no_self_loops(self):
        g = _generate_random_graph(15)
        for u, v in g:
            assert u != v

    def test_empty_graph_at_zero_probability(self):
        g = _generate_random_graph(10, edge_probability=0.0)
        assert len(g) == 0


# ---------------------------------------------------------------------------
# ZKP scheme tests
# ---------------------------------------------------------------------------

class TestGraphIsomorphismZKP:

    @pytest.fixture
    def scheme(self):
        return GraphIsomorphismZKP(num_vertices=15)

    @pytest.fixture
    def prover_verifier(self, scheme):
        return scheme.generate_params()

    def test_generate_params_returns_correct_types(self, prover_verifier):
        prover, verifier = prover_verifier
        assert isinstance(prover, GraphIsomorphismProver)
        assert isinstance(verifier, GraphIsomorphismVerifier)

    def test_g1_is_isomorphic_to_g0(self, prover_verifier):
        """G1 must have the same edge count as G0 (necessary for isomorphism)."""
        prover, _ = prover_verifier
        params = prover.setup()
        assert len(params["g0"]) == len(params["g1"])

    def test_honest_prover_accepted_single_round(self, prover_verifier):
        prover, verifier = prover_verifier
        commitment = prover.commit()
        challenge  = verifier.challenge(commitment)
        response   = prover.respond(challenge)
        assert verifier.verify(commitment, challenge, response) is True

    def test_honest_prover_accepted_40_rounds(self, scheme):
        prover, verifier = scheme.generate_params()
        assert run_zkp_protocol(prover, verifier, rounds=40) is True

    def test_respond_without_commit_raises(self, prover_verifier):
        prover, _ = prover_verifier
        with pytest.raises(RuntimeError, match="commit()"):
            prover.respond(0)

    def test_challenge_is_0_or_1(self, prover_verifier):
        prover, verifier = prover_verifier
        challenges = set()
        for _ in range(100):
            c = prover.commit()
            challenges.add(verifier.challenge(c))
        assert challenges == {0, 1}

    def test_dishonest_prover_rejected(self):
        """
        A prover who doesn't know π cannot answer both challenges.
        Over 40 rounds, expected failures > 0 with overwhelming probability.

        We simulate a dishonest prover by using a WRONG isomorphism.
        """
        from crypto.zkp.graph_iso import (
            _generate_random_graph, _random_permutation, _apply_permutation
        )

        # G0 and G1 are NOT isomorphic (G1 is a fresh random graph)
        n  = 15
        g0 = _generate_random_graph(n, 0.4)
        g1 = _generate_random_graph(n, 0.4)  # Independent — not isomorphic to G0
        wrong_pi = _random_permutation(n)     # Wrong witness

        prover   = GraphIsomorphismProver(g0, g1, wrong_pi)
        verifier = GraphIsomorphismVerifier(g0, g1)

        # Over 40 rounds, a dishonest prover should fail at least once
        # (probability of passing all 40 rounds: 2^-40 ≈ 10^-12)
        results = []
        for _ in range(40):
            commitment = prover.commit()
            challenge  = verifier.challenge(commitment)
            response   = prover.respond(challenge)
            results.append(verifier.verify(commitment, challenge, response))

        # At least some rounds must fail for a truly dishonest prover
        assert not all(results), "Dishonest prover should not pass all rounds"

    def test_scheme_name(self, scheme):
        assert "Graph Isomorphism" in scheme.name

    def test_hardness_assumption(self, scheme):
        assert "combinatorial" in scheme.hardness_assumption.lower()

    def test_multiple_independent_sessions(self, scheme):
        """Each generate_params() call produces an independent session."""
        for _ in range(5):
            prover, verifier = scheme.generate_params()
            assert run_zkp_protocol(prover, verifier, rounds=10) is True