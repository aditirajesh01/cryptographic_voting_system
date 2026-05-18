"""
server.py

Threaded TCP server for the cryptographic voting system.

Protocol per connection (all messages after DH are AES-256-CBC encrypted):

    1. DH handshake         — exchange public keys, derive session key
    2. Voter identification — receive voter_id
    3. RSA challenge-response — authenticate voter identity
    4. ZKP                  — graph isomorphism proof of eligibility
    5. Token issuance        — send anti-replay token + candidate list
    6. Vote reception        — receive vote + token, store, audit chain

Usage:
    python server.py [--host HOST] [--port PORT] [--db DB_PATH]

Defaults:
    host: 127.0.0.1
    port: 65432
    db:   voting.db
"""

import socket
import threading
import json
import secrets
import struct
import argparse
import sys
from typing import Optional

from crypto.dh import DHKeyExchange
from crypto.aes import aes_encrypt, aes_decrypt
from crypto.rsa import RSAPublicKey, rsa_encrypt, rsa_decrypt
from crypto.hmac_chain import HMACChain
from crypto.tokens import TokenManager
from crypto.zkp.graph_iso import GraphIsomorphismZKP
from crypto.zkp.base import run_zkp_protocol
from db import Database

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 65432
DEFAULT_DB   = "voting.db"
ZKP_ROUNDS   = 40
BUFFER_SIZE  = 4096


# ---------------------------------------------------------------------------
# TCP framing helpers
# Length-prefix framing: 4-byte big-endian length + payload
# ---------------------------------------------------------------------------

def send_message(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed message."""
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)


def recv_message(sock: socket.socket) -> bytes:
    """
    Receive a length-prefixed message.

    Raises:
        ConnectionError: If the connection is closed mid-receive.
    """
    # Read 4-byte length header
    header = _recv_exactly(sock, 4)
    length = struct.unpack(">I", header)[0]
    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), BUFFER_SIZE))
        if not chunk:
            raise ConnectionError("Connection closed by peer.")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Encrypted message helpers
# ---------------------------------------------------------------------------

def send_encrypted(sock: socket.socket, data: bytes, session_key: bytes) -> None:
    """Encrypt then send."""
    send_message(sock, aes_encrypt(data, session_key))


def recv_encrypted(sock: socket.socket, session_key: bytes) -> bytes:
    """Receive then decrypt."""
    return aes_decrypt(recv_message(sock), session_key)


def send_json(sock: socket.socket, obj: dict, session_key: bytes) -> None:
    """Serialize dict to JSON, encrypt, send."""
    send_encrypted(sock, json.dumps(obj).encode(), session_key)


def recv_json(sock: socket.socket, session_key: bytes) -> dict:
    """Receive, decrypt, deserialize JSON."""
    return json.loads(recv_encrypted(sock, session_key).decode())


# ---------------------------------------------------------------------------
# Voter session handler
# ---------------------------------------------------------------------------

class VoterSession:
    """
    Handles a single voter's connection from DH handshake to vote storage.
    Runs in its own thread.
    """

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple,
        db: Database,
        chain: HMACChain,
        token_manager: TokenManager,
        candidates: list[dict],
        lock: threading.Lock,
    ):
        self.conn          = conn
        self.addr          = addr
        self.db            = db
        self.chain         = chain
        self.token_manager = token_manager
        self.candidates    = candidates
        self.lock          = lock
        self.session_key: Optional[bytes] = None

    def run(self) -> None:
        """Entry point for the voter session thread."""
        try:
            print(f"[+] Connection from {self.addr}")
            self._dh_handshake()
            voter_id = self._identify_voter()
            if voter_id is None:
                return
            if not self._rsa_challenge_response(voter_id):
                return
            if not self._zkp_proof(voter_id):
                return
            self._handle_vote(voter_id)
        except (ConnectionError, OSError) as e:
            print(f"[-] Connection error from {self.addr}: {e}")
        except Exception as e:
            print(f"[-] Unexpected error in session {self.addr}: {e}")
        finally:
            self.conn.close()
            print(f"[+] Connection closed: {self.addr}")

    # ------------------------------------------------------------------
    # Step 1: DH handshake
    # ------------------------------------------------------------------

    def _dh_handshake(self) -> None:
        """
        Perform DH key exchange and derive AES session key.

        Server sends its DH public key first, then receives client's.
        """
        dh = DHKeyExchange()

        # Send server public key
        send_message(self.conn, str(dh.get_public_key()).encode())

        # Receive client public key
        client_pub = int(recv_message(self.conn).decode())

        # Derive session key
        self.session_key = dh.derive_session_key(client_pub)
        print(f"[+] DH handshake complete: {self.addr}")

    # ------------------------------------------------------------------
    # Step 2: Voter identification
    # ------------------------------------------------------------------

    def _identify_voter(self) -> Optional[str]:
        """
        Receive voter_id and check they are registered and haven't voted.

        Returns:
            voter_id string if valid, None if rejected.
        """
        msg = recv_json(self.conn, self.session_key)
        voter_id = msg.get("voter_id", "").strip()

        voter = self.db.get_voter(voter_id)
        if voter is None:
            send_json(self.conn, {"status": "error", "reason": "Voter not registered."}, self.session_key)
            print(f"[-] Unknown voter_id '{voter_id}' from {self.addr}")
            return None

        if voter["has_voted"]:
            send_json(self.conn, {"status": "error", "reason": "Voter has already voted."}, self.session_key)
            print(f"[-] Voter '{voter_id}' has already voted.")
            return None

        send_json(self.conn, {"status": "ok", "name": voter["name"]}, self.session_key)
        print(f"[+] Voter identified: {voter_id} ({voter['name']})")
        return voter_id

    # ------------------------------------------------------------------
    # Step 3: RSA challenge-response authentication
    # ------------------------------------------------------------------

    def _rsa_challenge_response(self, voter_id: str) -> bool:
        """
        Authenticate voter by RSA challenge-response.

        Server generates a random challenge, encrypts it with voter's
        public key, sends it. Voter decrypts and returns the plaintext.
        Server verifies the response matches.

        Returns:
            True if authentication succeeds, False otherwise.
        """
        voter = self.db.get_voter(voter_id)
        pub   = RSAPublicKey(n=voter["rsa_n"], e=voter["rsa_e"])

        # Generate 32-byte random challenge
        challenge = secrets.token_bytes(32)

        # Encrypt challenge with voter's RSA public key
        encrypted_challenge = rsa_encrypt(challenge, pub)

        # Send encrypted challenge
        send_json(self.conn, {
            "status": "challenge",
            "challenge": encrypted_challenge.hex(),
        }, self.session_key)

        # Receive response
        msg      = recv_json(self.conn, self.session_key)
        response = bytes.fromhex(msg.get("response", ""))

        if secrets.compare_digest(response, challenge):
            send_json(self.conn, {"status": "auth_ok"}, self.session_key)
            print(f"[+] RSA auth passed: {voter_id}")
            return True
        else:
            send_json(self.conn, {"status": "error", "reason": "RSA authentication failed."}, self.session_key)
            print(f"[-] RSA auth failed: {voter_id}")
            return False

    # ------------------------------------------------------------------
    # Step 4: ZKP — graph isomorphism proof of eligibility
    # ------------------------------------------------------------------

    def _zkp_proof(self, voter_id: str) -> bool:
        """
        Run graph isomorphism ZKP.

        Server acts as verifier. Client acts as prover.
        ZKP proves voter eligibility without linking identity to vote.

        Protocol runs over the network: for each round, server sends
        challenge, client sends commitment + response.

        Returns:
            True if ZKP passes all rounds, False otherwise.
        """
        # Generate fresh ZKP parameters for this session
        scheme   = GraphIsomorphismZKP(num_vertices=20)
        prover, verifier = scheme.generate_params()

        # Send public parameters (G0, G1, pi) to client
        # pi is sent to the client so it can act as prover.
        # In a real deployment, pi would be pre-distributed out-of-band;
        # here it is sent over the encrypted channel.
        params = prover.setup()
        send_json(self.conn, {
            "status":  "zkp_start",
            "rounds":  ZKP_ROUNDS,
            "g0":      [list(e) for e in params["g0"]],
            "g1":      [list(e) for e in params["g1"]],
            "n":       params["n"],
            "pi":      prover._pi,
        }, self.session_key)

        # Run ZKP rounds — server is verifier, client is prover
        for round_num in range(ZKP_ROUNDS):
            # Receive commitment from client (prover)
            msg        = recv_json(self.conn, self.session_key)
            client_commitment = frozenset(
                tuple(e) for e in msg.get("commitment", [])
            )

            # Server sends challenge
            challenge = verifier.challenge(client_commitment)
            send_json(self.conn, {"challenge": challenge}, self.session_key)

            # Receive response
            msg      = recv_json(self.conn, self.session_key)
            response = msg.get("response", [])

            # Verify
            if not verifier.verify(client_commitment, challenge, response):
                send_json(self.conn, {"status": "zkp_failed"}, self.session_key)
                print(f"[-] ZKP failed at round {round_num} for voter {voter_id}")
                return False

        send_json(self.conn, {"status": "zkp_passed"}, self.session_key)
        print(f"[+] ZKP passed: {voter_id}")
        return True

    # ------------------------------------------------------------------
    # Step 5 + 6: Issue token, receive and store vote
    # ------------------------------------------------------------------

    def _handle_vote(self, voter_id: str) -> None:
        """
        Issue anti-replay token, send candidate list, receive and store vote.
        """
        # Issue token and send candidate list
        token = self.token_manager.issue()
        send_json(self.conn, {
            "status":     "ready_to_vote",
            "token":      token.hex(),
            "candidates": self.candidates,
        }, self.session_key)

        # Receive vote
        msg            = recv_json(self.conn, self.session_key)
        candidate_id   = msg.get("candidate_id", "").strip()
        received_token = bytes.fromhex(msg.get("token", ""))

        # Validate token
        if not self.token_manager.consume(received_token):
            send_json(self.conn, {"status": "error", "reason": "Invalid or expired token."}, self.session_key)
            print(f"[-] Invalid token from voter {voter_id}")
            return

        # Validate candidate
        valid_ids = {c["id"] for c in self.candidates}
        if candidate_id not in valid_ids:
            send_json(self.conn, {"status": "error", "reason": "Invalid candidate."}, self.session_key)
            print(f"[-] Invalid candidate '{candidate_id}' from voter {voter_id}")
            return

        # Encrypt vote payload with session key before storing
        vote_payload     = json.dumps({"candidate_id": candidate_id}).encode()
        encrypted_vote   = aes_encrypt(vote_payload, self.session_key)

        # Thread-safe: lock before writing to DB and chain
        with self.lock:
            # Double-check has_voted under lock to prevent race condition
            if self.db.has_voted(voter_id):
                send_json(self.conn, {"status": "error", "reason": "Voter has already voted."}, self.session_key)
                return

            chain_entry = self.chain.append(encrypted_vote)
            self.db.store_vote(encrypted_vote, chain_entry)
            self.db.mark_voted(voter_id)

        send_json(self.conn, {"status": "vote_accepted"}, self.session_key)
        print(f"[+] Vote accepted from voter {voter_id} — candidate {candidate_id}")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class VotingServer:
    """
    Threaded TCP voting server.

    Accepts one connection per registered voter. Each connection runs
    in a dedicated thread. The DB, HMAC chain, and token manager are
    shared across threads (protected by a lock for writes).
    """

    def __init__(self, host: str, port: int, db_path: str):
        self.host          = host
        self.port          = port
        self.db            = Database(db_path)
        self.chain         = HMACChain(HMACChain.generate_chain_key())
        self.token_manager = TokenManager()
        self.lock          = threading.Lock()
        self.candidates    = self._load_candidates()

    def _load_candidates(self) -> list[dict]:
        """Load candidate list from candidates.json."""
        try:
            with open("candidates.json") as f:
                data = json.load(f)
            candidates = data.get("candidates", [])
            if not candidates:
                print("[!] Warning: candidates.json has no candidates.")
            return candidates
        except FileNotFoundError:
            print("[!] candidates.json not found. Using empty candidate list.")
            return []
        except json.JSONDecodeError as e:
            print(f"[!] Invalid candidates.json: {e}")
            return []

    def start(self) -> None:
        """Start the server and listen for connections."""
        self.db.init_schema()

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(10)

        print("=" * 60)
        print("  CRYPTOGRAPHIC VOTING SYSTEM — SERVER")
        print("=" * 60)
        print(f"  Listening on {self.host}:{self.port}")
        print(f"  Candidates loaded: {len(self.candidates)}")
        print(f"  Press Ctrl+C to stop.\n")

        try:
            while True:
                conn, addr = server_sock.accept()
                session = VoterSession(
                    conn=conn,
                    addr=addr,
                    db=self.db,
                    chain=self.chain,
                    token_manager=self.token_manager,
                    candidates=self.candidates,
                    lock=self.lock,
                )
                thread = threading.Thread(target=session.run, daemon=True)
                thread.start()
        except KeyboardInterrupt:
            print("\n[+] Server shutting down.")
        finally:
            server_sock.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Cryptographic Voting System Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Port to bind to")
    parser.add_argument("--db",   default=DEFAULT_DB,   help="Path to SQLite database")
    args = parser.parse_args()

    server = VotingServer(host=args.host, port=args.port, db_path=args.db)
    server.start()


if __name__ == "__main__":
    main()