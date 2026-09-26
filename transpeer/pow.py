"""EquiX proof-of-work wrapper using ctypes."""

import ctypes
import hashlib
import os
import struct
import time
from pathlib import Path

# EquiX constants
EQUIX_MAX_SOLS = 8
EQUIX_SOLUTION_SIZE = 16  # 8 x uint16_t
EQUIX_OK = 0
EQUIX_CTX_SOLVE = 1
EQUIX_CTX_VERIFY = 2

# Locate the shared library
_LIB_SEARCH_PATHS = [
    Path(__file__).parent.parent / "equix" / "libequix.so",
    Path("/usr/local/lib/libequix.so"),
    Path("/usr/lib/libequix.so"),
]

_lib = None


class EquixSolution(ctypes.Structure):
    _fields_ = [("idx", ctypes.c_uint16 * 8)]


def _load_lib():
    global _lib
    if _lib is not None:
        return _lib

    for path in _LIB_SEARCH_PATHS:
        if path.exists():
            _lib = ctypes.CDLL(str(path))
            _setup_bindings(_lib)
            return _lib

    raise RuntimeError(
        "libequix.so not found. Run: python equix/build.py"
    )


def _setup_bindings(lib):
    lib.equix_alloc.argtypes = [ctypes.c_int]
    lib.equix_alloc.restype = ctypes.c_void_p

    lib.equix_free.argtypes = [ctypes.c_void_p]
    lib.equix_free.restype = None

    lib.equix_solve.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(EquixSolution),
    ]
    lib.equix_solve.restype = ctypes.c_int

    lib.equix_verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(EquixSolution),
    ]
    lib.equix_verify.restype = ctypes.c_int


def build_challenge(network: str, addr: str, port: int, timestamp_bucket: int | None = None) -> bytes:
    if timestamp_bucket is None:
        timestamp_bucket = int(time.time()) // 21600
    data = f"{network}:{addr}:{port}:{timestamp_bucket}".encode()
    return hashlib.blake2b(data, digest_size=32).digest()


# Handshake PoW — bucket is 1 hour for faster turnover under attack
HANDSHAKE_BUCKET_SECS = 3600


def build_handshake_challenge(client_ip: str, server_node_id: str,
                              bucket: int | None = None) -> bytes:
    """Build a handshake PoW challenge bound to client IP, time bucket, and server node.

    This prevents reuse across different clients and makes the proof expire.
    A client can cache a valid proof for ~1 hour of requests to the same server.
    """
    if bucket is None:
        bucket = int(time.time()) // HANDSHAKE_BUCKET_SECS
    data = f"handshake:{client_ip}:{server_node_id}:{bucket}".encode()
    return hashlib.blake2b(data, digest_size=32).digest()


def _check_difficulty(challenge: bytes, nonce: bytes, solution_bytes: bytes, effort: int) -> bool:
    h = hashlib.blake2b(challenge + nonce + solution_bytes, digest_size=4).digest()
    r = struct.unpack("<I", h)[0]
    return r * effort <= 0xFFFFFFFF


def _solution_to_bytes(sol: EquixSolution) -> bytes:
    return bytes(ctypes.cast(sol.idx, ctypes.POINTER(ctypes.c_uint8 * 16)).contents)


EQUIX_SOLUTION_BYTES = 16


def _bytes_to_solution(data: bytes) -> EquixSolution:
    if len(data) != EQUIX_SOLUTION_BYTES:
        raise ValueError(f"EquiX solution must be {EQUIX_SOLUTION_BYTES} bytes, got {len(data)}")
    sol = EquixSolution()
    ctypes.memmove(sol.idx, data, EQUIX_SOLUTION_BYTES)
    return sol


# Simulated solve time. A solution passes the difficulty check with
# probability about 1/effort, so the expected solve time is linear in
# effort: effort x (time per candidate solution). The constant is anchored
# at the reference machine's 4.1 s for effort 100, the value every
# simulation in docs/manuscript.md ran at. Below one solve's own cost the
# floor applies. Until 2026-09-26 this was a five-point table (1: 0.2,
# 10: 0.83, 50: 6.0, 100: 4.1, 500: 14.0) from single noisy benchmarks;
# it was not monotonic and only its 100-entry was ever exercised by the
# eclipse experiments (§8.2, handshake PoW, interpolated across it).
SIM_SOLVE_SECS_PER_EFFORT = 4.1 / 100
SIM_SOLVE_FLOOR_SECS = 0.2


def _estimated_solve_time(effort: int) -> float:
    """Expected solve time for `effort` on the reference machine."""
    return max(SIM_SOLVE_FLOOR_SECS, SIM_SOLVE_SECS_PER_EFFORT * max(0, effort))


# Magic marker for simulated proofs — both solve and verify recognize this
_SIM_PROOF_MAGIC = b"SIMPOW"


def solve_simulated(network: str, addr: str, port: int, effort: int) -> tuple[bytes, bytes, int]:
    """Shadow-compatible EquiX solve that sleeps instead of computing.

    Uses time.sleep() to simulate the CPU cost — Shadow intercepts sleep
    and advances simulated time. Returns a proof tagged with a magic marker
    that verify_simulated() will accept.
    """
    solve_time = _estimated_solve_time(effort)
    time.sleep(solve_time)

    timestamp_bucket = int(time.time()) // 21600
    # Embed magic marker so verify_simulated knows this is a valid sim proof
    nonce = _SIM_PROOF_MAGIC + os.urandom(10)
    solution = os.urandom(16)
    return nonce, solution, timestamp_bucket


def verify_simulated(network: str, addr: str, port: int, nonce: bytes,
                     effort: int, solution_bytes: bytes, timestamp_bucket: int) -> bool:
    """Shadow-compatible verify that accepts simulated proofs."""
    if nonce[:len(_SIM_PROOF_MAGIC)] == _SIM_PROOF_MAGIC:
        return True
    # Fall through to real verification for non-simulated proofs
    return verify(network, addr, port, nonce, effort, solution_bytes, timestamp_bucket)


def solve(network: str, addr: str, port: int, effort: int) -> tuple[bytes, bytes, int]:
    """Solve an EquiX puzzle for a peer entry.

    Returns (nonce, solution_bytes, timestamp_bucket).
    """
    lib = _load_lib()
    ctx = lib.equix_alloc(EQUIX_CTX_SOLVE)
    if not ctx:
        raise RuntimeError("Failed to allocate EquiX solve context")

    try:
        timestamp_bucket = int(time.time()) // 21600
        challenge = build_challenge(network, addr, port, timestamp_bucket)

        nonce_counter = 0
        while True:
            nonce = struct.pack("<Q", nonce_counter) + os.urandom(8)
            full_challenge = challenge + nonce

            solutions = (EquixSolution * EQUIX_MAX_SOLS)()
            num_sols = lib.equix_solve(
                ctx,
                full_challenge,
                len(full_challenge),
                solutions,
            )

            for i in range(num_sols):
                sol_bytes = _solution_to_bytes(solutions[i])
                if _check_difficulty(challenge, nonce, sol_bytes, effort):
                    return nonce, sol_bytes, timestamp_bucket

            nonce_counter += 1
    finally:
        lib.equix_free(ctx)


def verify(network: str, addr: str, port: int, nonce: bytes,
           effort: int, solution_bytes: bytes, timestamp_bucket: int) -> bool:
    """Verify an EquiX proof-of-work for a peer entry."""
    lib = _load_lib()
    ctx = lib.equix_alloc(EQUIX_CTX_VERIFY)
    if not ctx:
        raise RuntimeError("Failed to allocate EquiX verify context")

    try:
        # Accept current and previous timestamp bucket
        current_bucket = int(time.time()) // 21600
        if timestamp_bucket not in (current_bucket, current_bucket - 1):
            return False

        challenge = build_challenge(network, addr, port, timestamp_bucket)
        full_challenge = challenge + nonce

        try:
            sol = _bytes_to_solution(solution_bytes)
        except ValueError:
            return False
        result = lib.equix_verify(ctx, full_challenge, len(full_challenge), ctypes.byref(sol))

        if result != EQUIX_OK:
            return False

        return _check_difficulty(challenge, nonce, solution_bytes, effort)
    finally:
        lib.equix_free(ctx)


def solve_handshake(client_ip: str, server_node_id: str, effort: int,
                    simulated: bool = False) -> tuple[bytes, bytes, int]:
    """Solve an EquiX PoW for a handshake challenge.

    Returns (nonce, solution_bytes, bucket).
    """
    bucket = int(time.time()) // HANDSHAKE_BUCKET_SECS

    if simulated:
        time.sleep(_estimated_solve_time(effort))
        nonce = _SIM_PROOF_MAGIC + os.urandom(10)
        solution = os.urandom(16)
        return nonce, solution, bucket

    lib = _load_lib()
    ctx = lib.equix_alloc(EQUIX_CTX_SOLVE)
    if not ctx:
        raise RuntimeError("Failed to allocate EquiX solve context")

    try:
        challenge = build_handshake_challenge(client_ip, server_node_id, bucket)
        nonce_counter = 0
        while True:
            nonce = struct.pack("<Q", nonce_counter) + os.urandom(8)
            full_challenge = challenge + nonce

            solutions = (EquixSolution * EQUIX_MAX_SOLS)()
            num_sols = lib.equix_solve(
                ctx, full_challenge, len(full_challenge), solutions,
            )
            for i in range(num_sols):
                sol_bytes = _solution_to_bytes(solutions[i])
                if _check_difficulty(challenge, nonce, sol_bytes, effort):
                    return nonce, sol_bytes, bucket
            nonce_counter += 1
    finally:
        lib.equix_free(ctx)


def verify_handshake(client_ip: str, server_node_id: str, nonce: bytes,
                     effort: int, solution_bytes: bytes, bucket: int,
                     accept_simulated: bool = False) -> bool:
    """Verify an EquiX handshake PoW."""
    # Fast path for simulation: tagged proofs accepted if bucket is current/previous
    current = int(time.time()) // HANDSHAKE_BUCKET_SECS
    if bucket not in (current, current - 1):
        return False

    if accept_simulated and nonce[:len(_SIM_PROOF_MAGIC)] == _SIM_PROOF_MAGIC:
        return True

    lib = _load_lib()
    ctx = lib.equix_alloc(EQUIX_CTX_VERIFY)
    if not ctx:
        raise RuntimeError("Failed to allocate EquiX verify context")
    try:
        challenge = build_handshake_challenge(client_ip, server_node_id, bucket)
        full_challenge = challenge + nonce
        try:
            sol = _bytes_to_solution(solution_bytes)
        except ValueError:
            return False
        result = lib.equix_verify(ctx, full_challenge, len(full_challenge), ctypes.byref(sol))
        if result != EQUIX_OK:
            return False
        return _check_difficulty(challenge, nonce, solution_bytes, effort)
    finally:
        lib.equix_free(ctx)
