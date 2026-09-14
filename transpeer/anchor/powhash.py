"""Pluggable proof-of-work hash for the anchor chain and P2Pool shares.

RandomX is Monero's production hash; it needs a native binding and a
seed-hash-selected dataset, both expensive to set up under Shadow.
Simulations opt into SHA-256 instead with --anchor-sim-pow so every
node stays comparable across runs without carrying RandomX's per-host
memory and CPU cost.
"""

import hashlib
from typing import Protocol


class PowUnavailable(RuntimeError):
    pass


class PowBackend(Protocol):
    name: str

    def hash(self, blob: bytes, height: int, seed_hash: bytes) -> bytes:
        ...


class Sha256Pow:
    name = "sha256"

    def hash(self, blob: bytes, height: int, seed_hash: bytes) -> bytes:
        return hashlib.sha256(blob).digest()


class RandomXPow:
    name = "randomx"

    def __init__(self, randomx_module):
        self._randomx = randomx_module

    def hash(self, blob: bytes, height: int, seed_hash: bytes) -> bytes:
        # height is informational only (logging); seed_hash selects the
        # dataset the caller received with the block header, or zeros.
        return self._randomx.RandomX(seed_hash, full_mem=False).hash(blob)


def randomx_backend() -> PowBackend:
    try:
        import randomx
    except ImportError as e:
        raise PowUnavailable(
            "RandomX binding not installed; use --anchor-sim-pow for simulation"
        ) from e
    return RandomXPow(randomx)


def backend_for(config) -> PowBackend:
    return Sha256Pow() if config.anchor_sim_pow else randomx_backend()


def mine(make_blob, difficulty: int, pow: PowBackend, height: int = 0,
          seed_hash: bytes = bytes(32), max_nonce: int = 1 << 32) -> tuple:
    from transpeer.anchor.monero import check_hash

    for nonce in range(max_nonce):
        blob = make_blob(nonce)
        if check_hash(pow.hash(blob, height, seed_hash), difficulty):
            return nonce, blob
    raise ValueError(f"exhausted {max_nonce} nonces without meeting difficulty {difficulty}")
