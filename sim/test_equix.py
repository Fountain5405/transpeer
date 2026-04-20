#!/usr/bin/env python3
"""Test EquiX solve/verify inside Shadow."""
import sys
sys.path.insert(0, "/home/lever65/transpeer")

from transpeer.pow import solve, verify
import time

print("Testing EquiX solve...")
t0 = time.time()
nonce, sol, bucket = solve("test", "1.2.3.4", 8080, effort=1)
t1 = time.time()
print(f"Solved in {t1-t0:.3f}s: nonce={nonce.hex()}, solution={sol.hex()}")

print("Testing EquiX verify (valid)...")
valid = verify("test", "1.2.3.4", 8080, nonce, 1, sol, bucket)
print(f"Valid proof: {valid}")

print("Testing EquiX verify (invalid)...")
bad = verify("test", "1.2.3.4", 8080, nonce, 1, sol, bucket - 5)
print(f"Bad proof: {bad}")

if valid and not bad:
    print("EQUIX TEST PASSED")
else:
    print("EQUIX TEST FAILED")
    sys.exit(1)
