"""
crypto/zkp/graph_iso.py

Zero-Knowledge Proof of graph isomorphism.

Hardness assumption: Graph Isomorphism (GI) — no known polynomial-time
algorithm exists for GI in the general case (Babai, 2016 showed
quasipolynomial but not polynomial). This is a combinatorial hardness
assumption, distinct from number-theoretic assumptions used by Schnorr
and GQ.

Protocol (Goldreich, Micali, Wigderson 1991 — interactive proof for GI):
    Public:  G0, G1 (two isomorphic graphs)
    Witness: π (permutation such that π(G0) = G1)

    For each round:
        1. Prover picks random permutation σ, computes H = σ(G0), sends H
        2. Verifier sends challenge bit b ∈ {0, 1}
        3. If b=0: Prover sends σ         (Verifier checks σ(G0) = H)
           If b=1: Prover sends σ ∘ π⁻¹  (Verifier checks that(G1) = H)
        4. Verifier accepts round if permutation is valid

    Soundness: A prover who doesn't know π can fool the verifier with
    probability at most 1/2 per round. After 40 rounds: 2^(-40) ≈ 10^(-12).

    Zero-knowledge: H is a uniformly random relabeling of G0, independent
    of π. The verifier learns nothing about π beyond its existence.

Usage:
    from crypto.zkp.graph_iso import GraphIsomorphismZKP
    from crypto.zkp.base import run_zkp_protocol

    scheme = GraphIsomorphismZKP(num_vertices=20)
    prover, verifier = scheme.generate_params()
    accepted = run_zkp_protocol(prover, verifier, rounds=40)
"""

import secrets
from typing import Any
from crypto.zkp.base import ZKPProver, ZKPVerifier, ZKPScheme


# ---------------------------------------------------------------------------
# Graph representation
# ---------------------------------------------------------------------------

# A graph is represented as a frozenset of edges: frozenset({(u, v), ...})
# where u < v (undirected). Vertices are integers in [0, n-1].

Graph = frozenset  # frozenset[tuple[int, int]]


def _apply_permutation(graph: Graph, perm: list[int]) -> Graph:
    """
    Apply a vertex permutation to a graph.

    Args:
        graph: Set of edges as (u, v) pairs with u < v.
        perm:  Permutation list where perm[i] is the new label of vertex i.

    Returns:
        New graph with relabeled vertices, edges normalized (u < v).
    """
    new_edges = set()
    for u, v in graph:
        a, b = perm[u], perm[v]
        new_edges.add((min(a, b), max(a, b)))
    return frozenset(new_edges)


def _random_permutation(n: int) -> list[int]:
    """Generate a uniformly random permutation of [0, n-1]."""
    perm = list(range(n))
    # Fisher-Yates shuffle using secrets for CSPRNG
    for i in range(n - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def _invert_permutation(perm: list[int]) -> list[int]:
    """Compute the inverse of a permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def _compose_permutations(perm_a: list[int], perm_b: list[int]) -> list[int]:
    """
    Compose two permutations: result[i] = perm_a[perm_b[i]].
    Applies perm_b first, then perm_a.
    """
    return [perm_a[perm_b[i]] for i in range(len(perm_a))]


def _generate_random_graph(n: int, edge_probability: float = 0.4) -> Graph:
    """
    Generate a random undirected graph on n vertices.

    Args:
        n: Number of vertices.
        edge_probability: Probability of each possible edge existing.

    Returns:
        Graph as frozenset of (u, v) edges with u < v.
    """
    edges = set()
    for u in range(n):
        for v in range(u + 1, n):
            # Use secrets.randbelow for unbiased random comparison
            if secrets.randbelow(1000) < int(edge_probability * 1000):
                edges.add((u, v))
    return frozenset(edges)


# ---------------------------------------------------------------------------
# Prover
# ---------------------------------------------------------------------------

class GraphIsomorphismProver(ZKPProver):
    """
    Prover for graph isomorphism ZKP.

    Knows the isomorphism π such that π(G0) = G1.
    """

    def __init__(self, g0: Graph, g1: Graph, pi: list[int]):
        """
        Args:
            g0:  First graph (public).
            g1:  Second graph (public).
            pi:  Isomorphism from G0 to G1 (secret witness).
        """
        self._g0  = g0
        self._g1  = g1
        self._pi  = pi           # π: G0 → G1
        self._n   = len(pi)
        self._sigma: list[int] | None = None  # Current round's random permutation

    def setup(self) -> dict:
        return {
            "g0": self._g0,
            "g1": self._g1,
            "n":  self._n,
        }

    def commit(self) -> Graph:
        """
        Pick a random permutation σ, compute H = σ(G0).
        H is the commitment for this round.
        """
        self._sigma = _random_permutation(self._n)
        return _apply_permutation(self._g0, self._sigma)

    def respond(self, challenge: int) -> list[int]:
        """
        Respond to challenge bit.

        If challenge = 0: reveal σ         (so verifier can check σ(G0) = H)
        If challenge = 1: reveal σ ∘ π⁻¹  (so verifier can check that(G1) = H)

        Args:
            challenge: 0 or 1.

        Returns:
            Permutation as a list of integers.
        """
        if self._sigma is None:
            raise RuntimeError("commit() must be called before respond().")
        if challenge == 0:
            return self._sigma
        else:
            # σ ∘ π⁻¹ maps G1 to H:
            # H = σ(G0) = σ(π⁻¹(G1))
            pi_inv = _invert_permutation(self._pi)
            return _compose_permutations(self._sigma, pi_inv)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class GraphIsomorphismVerifier(ZKPVerifier):
    """
    Verifier for graph isomorphism ZKP.

    Knows G0 and G1, verifies that the prover knows π without learning it.
    """

    def __init__(self, g0: Graph, g1: Graph):
        self._g0 = g0
        self._g1 = g1

    def challenge(self, commitment: Graph) -> int:
        """Send a random challenge bit: 0 or 1."""
        return secrets.randbelow(2)

    def verify(self, commitment: Graph, challenge: int, response: list[int]) -> bool:
        """
        Verify the prover's response.

        If challenge = 0: check response(G0) = commitment (H)
        If challenge = 1: check response(G1) = commitment (H)

        Args:
            commitment: H — the graph sent by the prover.
            challenge:  0 or 1.
            response:   Permutation sent by the prover.

        Returns:
            True if the permutation maps the correct source graph to H.
        """
        try:
            if challenge == 0:
                return _apply_permutation(self._g0, response) == commitment
            else:
                return _apply_permutation(self._g1, response) == commitment
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Scheme factory
# ---------------------------------------------------------------------------

class GraphIsomorphismZKP(ZKPScheme):
    """
    Graph Isomorphism ZKP scheme factory.

    Generates a random graph G0, a random isomorphism π, and derives G1 = π(G0).
    Returns configured prover and verifier instances.
    """

    ROUNDS = 40

    def __init__(self, num_vertices: int = 20, edge_probability: float = 0.4):
        """
        Args:
            num_vertices:    Number of vertices in the graphs.
                             20 is sufficient for demonstration; larger values
                             increase security but also benchmark time.
            edge_probability: Density of the random graph G0.
        """
        self._n    = num_vertices
        self._prob = edge_probability

    @property
    def name(self) -> str:
        return "Graph Isomorphism ZKP"

    @property
    def hardness_assumption(self) -> str:
        return "Graph Isomorphism (combinatorial hardness)"

    def generate_params(self) -> tuple[GraphIsomorphismProver, GraphIsomorphismVerifier]:
        """
        Generate G0, π, G1 = π(G0).

        Returns:
            (GraphIsomorphismProver, GraphIsomorphismVerifier)
        """
        g0 = _generate_random_graph(self._n, self._prob)
        pi = _random_permutation(self._n)
        g1 = _apply_permutation(g0, pi)

        prover   = GraphIsomorphismProver(g0, g1, pi)
        verifier = GraphIsomorphismVerifier(g0, g1)
        return prover, verifier