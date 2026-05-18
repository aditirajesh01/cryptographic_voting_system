"""
crypto/zkp/benchmark.py

Empirical benchmark comparing three ZKP schemes:

    1. Graph Isomorphism ZKP  — combinatorial hardness (GI assumption)
    2. Schnorr Sigma Protocol — discrete logarithm hardness (DLP)
    3. Guillou-Quisquater (GQ) — RSA assumption (integer factorization)

Metrics measured per scheme:
    - Setup time       : key/parameter generation (ms)
    - Commit time      : per-round commitment generation (ms)
    - Challenge time   : per-round challenge generation (ms)
    - Response time    : per-round response generation (ms)
    - Verify time      : per-round verification (ms)
    - Total round time : full single-round protocol (ms)
    - Proof size       : bytes transmitted per round (commitment + response)
    - Soundness error  : per-round probability of cheating prover succeeding

All timing measurements are averaged over TIMING_ITERATIONS runs to
reduce variance. Results are printed to stdout and saved to benchmark_results.json.

Usage:
    python crypto/zkp/benchmark.py
    python crypto/zkp/benchmark.py --iterations 100 --rounds 40 --output results.json
"""

import time
import json
import argparse
import sys
import statistics

from crypto.zkp.base import ZKPScheme, ZKPProver, ZKPVerifier
from crypto.zkp.graph_iso import GraphIsomorphismZKP
from crypto.zkp.schnorr import SchnorrZKP
from crypto.zkp.gq import GQZKP

# ---------------------------------------------------------------------------
# Default benchmark parameters
# ---------------------------------------------------------------------------

DEFAULT_ITERATIONS = 50    # Timing runs per measurement
DEFAULT_ROUNDS     = 40    # Protocol rounds (for graph iso)
DEFAULT_OUTPUT     = "benchmark_results.json"
GI_VERTICES        = 20    # Graph size for GI scheme


# ---------------------------------------------------------------------------
# Timing helper
# ---------------------------------------------------------------------------

def _time_call(fn, *args, iterations: int = 1) -> tuple[float, any]:
    """
    Time a function call over multiple iterations.

    Returns:
        (mean_ms, last_return_value)
    """
    times = []
    result = None
    for _ in range(iterations):
        start  = time.perf_counter()
        result = fn(*args)
        end    = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    return statistics.mean(times), result


# ---------------------------------------------------------------------------
# Proof size measurement
# ---------------------------------------------------------------------------

def _measure_proof_size_graph_iso(prover: ZKPProver, verifier: ZKPVerifier) -> int:
    """
    Measure bytes transmitted per round for Graph Isomorphism ZKP.

    Commitment: frozenset of edges serialized as list of pairs
    Response:   permutation list of integers
    """
    commitment = prover.commit()
    challenge  = verifier.challenge(commitment)
    response   = prover.respond(challenge)

    # Serialize as JSON (matches network protocol)
    commitment_bytes = len(json.dumps([list(e) for e in commitment]).encode())
    response_bytes   = len(json.dumps(response).encode())
    return commitment_bytes + response_bytes


def _measure_proof_size_schnorr(prover: ZKPProver, verifier: ZKPVerifier) -> int:
    """
    Measure bytes transmitted per round for Schnorr.

    Commitment: integer t (2048-bit → 256 bytes)
    Response:   integer s (2048-bit → 256 bytes)
    """
    commitment = prover.commit()
    challenge  = verifier.challenge(commitment)
    response   = prover.respond(challenge)

    commitment_bytes = (commitment.bit_length() + 7) // 8
    response_bytes   = (response.bit_length() + 7) // 8
    return commitment_bytes + response_bytes


def _measure_proof_size_gq(prover: ZKPProver, verifier: ZKPVerifier) -> int:
    """
    Measure bytes transmitted per round for GQ.

    Commitment: integer t (2048-bit → 256 bytes)
    Response:   integer s (2048-bit → 256 bytes)
    """
    commitment = prover.commit()
    challenge  = verifier.challenge(commitment)
    response   = prover.respond(challenge)

    commitment_bytes = (commitment.bit_length() + 7) // 8
    response_bytes   = (response.bit_length() + 7) // 8
    return commitment_bytes + response_bytes


# ---------------------------------------------------------------------------
# Per-scheme benchmark
# ---------------------------------------------------------------------------

def benchmark_scheme(
    scheme: ZKPScheme,
    iterations: int,
    rounds: int,
    proof_size_fn,
    label: str,
) -> dict:
    """
    Run full benchmark for one ZKP scheme.

    Args:
        scheme:         ZKPScheme instance.
        iterations:     Number of timing iterations per measurement.
        rounds:         Number of protocol rounds (relevant for GI).
        proof_size_fn:  Function to measure proof size in bytes.
        label:          Human-readable label for output.

    Returns:
        Dict of benchmark results.
    """
    print(f"\n  Benchmarking: {label}")
    print(f"  {'─' * 50}")

    # -- Setup time --
    print(f"  [1/5] Measuring setup time ({iterations} iterations)...", end=" ", flush=True)
    setup_ms, (prover, verifier) = _time_call(scheme.generate_params, iterations=iterations)
    print(f"{setup_ms:.3f} ms avg")

    # -- Commit time --
    print(f"  [2/5] Measuring commit time ({iterations} iterations)...", end=" ", flush=True)
    commit_ms, commitment = _time_call(prover.commit, iterations=iterations)
    print(f"{commit_ms:.3f} ms avg")

    # -- Challenge time --
    print(f"  [3/5] Measuring challenge time ({iterations} iterations)...", end=" ", flush=True)
    challenge_ms, challenge = _time_call(verifier.challenge, commitment, iterations=iterations)
    print(f"{challenge_ms:.3f} ms avg")

    # -- Response time --
    print(f"  [4/5] Measuring response time ({iterations} iterations)...", end=" ", flush=True)
    # Must re-commit before each respond (respond consumes the nonce)
    response_times = []
    for _ in range(iterations):
        c = prover.commit()
        ch = verifier.challenge(c)
        start = time.perf_counter()
        prover.respond(ch)
        response_times.append((time.perf_counter() - start) * 1000)
    response_ms = statistics.mean(response_times)
    print(f"{response_ms:.3f} ms avg")

    # -- Verify time --
    print(f"  [5/5] Measuring verify time ({iterations} iterations)...", end=" ", flush=True)
    verify_times = []
    for _ in range(iterations):
        c  = prover.commit()
        ch = verifier.challenge(c)
        r  = prover.respond(ch)
        start = time.perf_counter()
        verifier.verify(c, ch, r)
        verify_times.append((time.perf_counter() - start) * 1000)
    verify_ms = statistics.mean(verify_times)
    print(f"{verify_ms:.3f} ms avg")

    # -- Total single-round protocol time --
    total_round_ms = commit_ms + challenge_ms + response_ms + verify_ms

    # -- Full protocol time (all rounds) --
    full_protocol_ms = setup_ms + (total_round_ms * rounds)

    # -- Proof size --
    prover2, verifier2 = scheme.generate_params()
    proof_size_bytes = proof_size_fn(prover2, verifier2)

    # -- Soundness error --
    if label.startswith("Graph"):
        soundness_error = f"2^(-{rounds})"
        soundness_float = 2 ** (-rounds)
    else:
        # Schnorr: 1/2^128 per round; GQ: 1/e per round
        if label.startswith("Schnorr"):
            soundness_error = "2^(-128) per round"
            soundness_float = 2 ** (-128)
        else:
            soundness_error = "1/e ≈ 1.5×10^(-5) per round"
            soundness_float = 1 / 65537

    return {
        "scheme":              label,
        "hardness_assumption": scheme.hardness_assumption,
        "setup_ms":            round(setup_ms, 4),
        "commit_ms":           round(commit_ms, 4),
        "challenge_ms":        round(challenge_ms, 4),
        "response_ms":         round(response_ms, 4),
        "verify_ms":           round(verify_ms, 4),
        "total_round_ms":      round(total_round_ms, 4),
        "full_protocol_ms":    round(full_protocol_ms, 4),
        "proof_size_bytes":    proof_size_bytes,
        "rounds":              rounds,
        "soundness_error":     soundness_error,
        "soundness_float":     soundness_float,
        "iterations":          iterations,
    }


# ---------------------------------------------------------------------------
# Results display
# ---------------------------------------------------------------------------

def print_results_table(results: list[dict]) -> None:
    """Print a formatted comparison table to stdout."""
    print("\n")
    print("=" * 80)
    print("  ZKP SCHEME EMPIRICAL COMPARISON — RESULTS")
    print("=" * 80)

    metrics = [
        ("Setup time (ms)",        "setup_ms"),
        ("Commit time (ms)",       "commit_ms"),
        ("Response time (ms)",     "response_ms"),
        ("Verify time (ms)",       "verify_ms"),
        ("Total round time (ms)",  "total_round_ms"),
        ("Full protocol time (ms)","full_protocol_ms"),
        ("Proof size (bytes)",     "proof_size_bytes"),
        ("Soundness error",        "soundness_error"),
        ("Hardness assumption",    "hardness_assumption"),
    ]

    # Header
    col_w = 26
    header = f"  {'Metric':<28}" + "".join(f"{r['scheme'][:col_w]:<{col_w}}" for r in results)
    print(header)
    print("  " + "─" * (28 + col_w * len(results)))

    for label, key in metrics:
        row = f"  {label:<28}"
        for r in results:
            val = r[key]
            if isinstance(val, float):
                row += f"{val:<{col_w}.4f}"
            else:
                row += f"{str(val):<{col_w}}"
        print(row)

    print("=" * 80)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_benchmark(iterations: int, rounds: int, output: str) -> None:
    print("=" * 80)
    print("  ZKP SCHEME BENCHMARK — CRYPTOGRAPHIC VOTING SYSTEM")
    print("=" * 80)
    print(f"  Timing iterations : {iterations}")
    print(f"  Protocol rounds   : {rounds} (Graph Isomorphism)")
    print(f"  GI graph vertices : {GI_VERTICES}")
    print(f"  RSA/DH key size   : 2048 bits")
    print(f"  Output file       : {output}")
    print()
    print("  NOTE: Setup time for GQ involves RSA-2048 key generation.")
    print("        This may take several minutes depending on your machine.\n")

    results = []

    # -- Graph Isomorphism --
    gi_scheme = GraphIsomorphismZKP(num_vertices=GI_VERTICES)
    gi_result = benchmark_scheme(
        scheme        = gi_scheme,
        iterations    = iterations,
        rounds        = rounds,
        proof_size_fn = _measure_proof_size_graph_iso,
        label         = "Graph Isomorphism ZKP",
    )
    results.append(gi_result)

    # -- Schnorr --
    schnorr_scheme = SchnorrZKP()
    schnorr_result = benchmark_scheme(
        scheme        = schnorr_scheme,
        iterations    = iterations,
        rounds        = 1,
        proof_size_fn = _measure_proof_size_schnorr,
        label         = "Schnorr Sigma Protocol",
    )
    results.append(schnorr_result)

    # -- GQ --
    gq_scheme = GQZKP(bits=2048)
    gq_result = benchmark_scheme(
        scheme        = gq_scheme,
        iterations    = iterations,
        rounds        = 1,
        proof_size_fn = _measure_proof_size_gq,
        label         = "Guillou-Quisquater (GQ)",
    )
    results.append(gq_result)

    # Print table
    print_results_table(results)

    # Save JSON
    output_data = {
        "benchmark_params": {
            "timing_iterations": iterations,
            "gi_rounds":         rounds,
            "gi_vertices":       GI_VERTICES,
            "key_size_bits":     2048,
        },
        "results": results,
    }
    with open(output, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\n  Results saved to: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZKP Scheme Empirical Benchmark"
    )
    parser.add_argument(
        "--iterations", type=int, default=DEFAULT_ITERATIONS,
        help=f"Timing iterations per measurement (default: {DEFAULT_ITERATIONS})"
    )
    parser.add_argument(
        "--rounds", type=int, default=DEFAULT_ROUNDS,
        help=f"Protocol rounds for Graph Isomorphism (default: {DEFAULT_ROUNDS})"
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output JSON file (default: {DEFAULT_OUTPUT})"
    )
    args = parser.parse_args()

    run_benchmark(
        iterations = args.iterations,
        rounds     = args.rounds,
        output     = args.output,
    )


if __name__ == "__main__":
    main()