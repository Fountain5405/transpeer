#!/usr/bin/env python3
"""Unit checks for the scanner's etiquette profile. No network.

Run:  python tests/test_scanner.py
"""

import asyncio
import ipaddress
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transpeer.config import Config, SCAN_CONCURRENCY  # noqa: E402
from transpeer.peerstore import PeerStore, TranspeerEntry  # noqa: E402
from transpeer.scanner import Scanner, load_exclusions, random_ip  # noqa: E402

passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


class RecordingScanner(Scanner):
    """Records probe targets and timestamps instead of touching the network."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.probes = []

    async def _probe_ip(self, addr):
        self.probes.append((addr, time.monotonic()))
        return False


def mk(store, **cfg):
    return RecordingScanner(Config(in_memory=True, **cfg), store, client=None)


async def add_live(store, n):
    """n transpeers that have answered a query."""
    for i in range(n):
        addr = f"11.{i // 250}.{i % 250}.1"
        await store.add_transpeer(TranspeerEntry(addr=addr, port=7337))
        store.mark_queried(addr, 7337, answered=True)


def test_exclusions():
    print("\n=== Exclude file ===")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("# comment line\n\n11.0.0.0/8   # trailing comment\n203.0.113.0/24\n")
        path = f.name
    try:
        ranges = load_exclusions(path)
        check(len(ranges) == 2 and ranges[0] == (int(ipaddress.IPv4Address("11.0.0.0")),
                                                  int(ipaddress.IPv4Address("11.255.255.255"))),
              "exclude file parses prefixes, skips comments and blank lines")
        hits = sum(1 for _ in range(3000) if random_ip(ranges).startswith("11."))
        check(hits == 0, "blind random_ip never lands in an excluded /8 (3000 draws)")
        reserved = sum(1 for _ in range(3000)
                       if ipaddress.IPv4Address(random_ip()).is_private)
        check(reserved == 0, "blind random_ip never lands in a private range (3000 draws)")
        dod = ("6.", "7.", "11.", "21.", "22.", "26.", "28.", "29.", "30.", "33.", "55.", "214.", "215.")
        sens = sum(1 for _ in range(3000) if random_ip().startswith(dod))
        legacy_sens = sum(1 for _ in range(3000)
                          if random_ip(skip_sensitive=False).startswith(dod))
        check(sens == 0 and legacy_sens > 0,
              "blind random_ip skips the sensitive /8s by default and not under legacy (3000 draws)")
        with open(path, "a") as f:
            f.write("not-a-prefix\n")
        try:
            load_exclusions(path)
            check(False, "a malformed line is an error")
        except ValueError as e:
            check("not-a-prefix" in str(e), "a malformed line is an error naming the line")
    finally:
        os.unlink(path)
    check(load_exclusions(None) == [], "no exclude file means no exclusions")


async def test_rate_selection():
    print("\n=== Rate selection ===")
    s = PeerStore(Config(in_memory=True))
    sc = mk(s, scan_rate=4.0, scan_idle_rate=0.2, scan_target_known=5)
    check(sc.current_rate() == 4.0 and sc._batch_size() == 40,
          "empty store: cold rate, 4/s over a 10 s interval is 40 probes")
    await s.add_transpeer(TranspeerEntry(addr="11.9.9.9", port=7337))
    for _ in range(5):
        await s.add_transpeer(TranspeerEntry(addr=f"11.8.8.{_ + 1}", port=7337))
    check(sc.current_rate() == 4.0, "known but unanswered transpeers do not count as live")
    await add_live(s, 5)
    check(sc.current_rate() == 0.2 and sc._batch_size() == 2,
          "at the live target: idle rate, 0.2/s is 2 probes per interval")
    s.mark_queried("11.0.0.1", 7337, answered=False)
    s.mark_queried("11.0.1.1", 7337, answered=False)
    s.mark_queried("11.0.2.1", 7337, answered=False)
    check(sc.current_rate() == 4.0, "when live transpeers stop answering, scanning resumes")
    d = mk(PeerStore(Config(in_memory=True)))
    check(d.config.scan_idle_rate == 0.0 and d.config.scan_target_known == 3,
          "default profile: stop scanning after 3 live transpeers")
    s3 = PeerStore(Config(in_memory=True))
    await add_live(s3, 3)
    check(mk(s3)._batch_size() == 0, "default profile: batch size 0 once 3 transpeers are live")
    sc0 = mk(s, scan_rate=0.0, scan_idle_rate=0.0)
    check(sc0._batch_size() == 0, "rate 0 disables blind scanning")
    legacy = mk(PeerStore(Config(in_memory=True)), scan_legacy=True)
    check(legacy._batch_size() == SCAN_CONCURRENCY,
          f"legacy profile keeps bursts of {SCAN_CONCURRENCY}")
    legacy_range = mk(PeerStore(Config(in_memory=True)), scan_legacy=True, scan_range="11.0.0.0/24")
    check(legacy_range._batch_size() == 127, "legacy profile scans half an explicit range per batch")


async def test_pacing():
    print("\n=== Pacing ===")
    s = PeerStore(Config(in_memory=True))
    sc = mk(s, scan_rate=4.0, scan_target_known=100)
    sc.interval = 0.5  # shrink the interval so the test runs in half a second
    t0 = time.monotonic()
    await sc.scan_batch()
    elapsed = time.monotonic() - t0
    check(len(sc.probes) == 2, "batch size follows rate x interval (4/s x 0.5 s = 2)")
    gaps = [b[1] - a[1] for a, b in zip(sc.probes, sc.probes[1:])]
    check(all(g >= 0.1 for g in gaps) and elapsed >= 0.2,
          "paced probes are spread across the interval with jitter, not fired at once")
    legacy = mk(PeerStore(Config(in_memory=True)), scan_legacy=True, scan_range="11.0.0.0/28")
    t0 = time.monotonic()
    await legacy.scan_batch()
    check(len(legacy.probes) == 7 and time.monotonic() - t0 < 0.1,
          "legacy batch fires all probes at once")
    ex = mk(PeerStore(Config(in_memory=True)), scan_range="11.0.0.0/24", scan_rate=4.0)
    ex.interval = 0.25
    await ex.scan_batch()
    check(all(p[0].startswith("11.0.0.") for p in ex.probes), "an explicit scan range is honoured")


async def main():
    test_exclusions()
    await test_rate_selection()
    await test_pacing()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
