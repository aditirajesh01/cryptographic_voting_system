"""
crypto/zkp/base.py

Abstract base class for all ZKP scheme implementations.

All three schemes (GraphIsomorphismZKP, SchnorrZKP, GQZKP) implement
this interface, enabling the benchmark script to treat them uniformly.

Prover and Verifier are separated into distinct classes to reflect the
actual protocol structure — in the real system, the voter is the Prover
and the server is the Verifier, communicating over the network.
"""

from abc import ABC, abstractmethod
from typing import Any


class ZKPProver(ABC):
    """Abstract prover — holds the witness (secret) and generates proofs."""

    @abstractmethod
    def setup(self) -> dict:
        """
        Generate public parameters and the prover's witness.

        Returns:
            Dict containing public parameters to share with the verifier.
            The witness (secret) is stored internally and never returned.
        """

    @abstractmethod
    def commit(self) -> Any:
        """
        Generate a commitment for one proof round.

        Returns:
            Commitment value to send to the verifier.
        """

    @abstractmethod
    def respond(self, challenge: Any) -> Any:
        """
        Generate a response to the verifier's challenge.

        Args:
            challenge: The verifier's challenge value.

        Returns:
            Response value to send to the verifier.
        """


class ZKPVerifier(ABC):
    """Abstract verifier — checks proofs without learning the witness."""

    @abstractmethod
    def challenge(self, commitment: Any) -> Any:
        """
        Generate a challenge in response to the prover's commitment.

        Args:
            commitment: The prover's commitment value.

        Returns:
            Challenge value to send to the prover.
        """

    @abstractmethod
    def verify(self, commitment: Any, challenge: Any, response: Any) -> bool:
        """
        Verify one round of the proof.

        Args:
            commitment: The prover's original commitment.
            challenge:  The verifier's challenge.
            response:   The prover's response.

        Returns:
            True if this round verifies, False otherwise.
        """


class ZKPScheme(ABC):
    """
    Factory class for a complete ZKP scheme.

    Encapsulates setup and provides prover/verifier instances.
    Used by the benchmark script to instantiate and measure each scheme.
    """

    # Number of rounds required for soundness error <= 2^(-ROUNDS)
    ROUNDS: int = 40

    @abstractmethod
    def generate_params(self) -> tuple[ZKPProver, ZKPVerifier]:
        """
        Generate all parameters and return configured prover/verifier pair.

        Returns:
            (ZKPProver, ZKPVerifier) ready to run the protocol.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scheme name for benchmark output."""

    @property
    @abstractmethod
    def hardness_assumption(self) -> str:
        """The hardness assumption this scheme relies on."""


def run_zkp_protocol(
    prover: ZKPProver,
    verifier: ZKPVerifier,
    rounds: int = 40,
) -> bool:
    """
    Run a complete ZKP protocol for the given number of rounds.

    Args:
        prover:   Configured ZKPProver instance.
        verifier: Configured ZKPVerifier instance.
        rounds:   Number of rounds. More rounds = lower soundness error.

    Returns:
        True if all rounds verify (prover is accepted), False otherwise.
    """
    for _ in range(rounds):
        commitment = prover.commit()
        challenge  = verifier.challenge(commitment)
        response   = prover.respond(challenge)
        if not verifier.verify(commitment, challenge, response):
            return False
    return True