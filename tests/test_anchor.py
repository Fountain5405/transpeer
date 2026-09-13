#!/usr/bin/env python3
"""Unit checks for transpeer.anchor: pure modules, no network.

Run:  PYTHONPATH=$PWD .venv/bin/python tests/test_anchor.py
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

passed = failed = 0


def check(cond, name):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")


def test_keccak():
    from transpeer.anchor.keccak import keccak256
    from transpeer.anchor import CHAIN_ID
    print("keccak256")
    check(keccak256(b"").hex()
          == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "empty input")
    check(keccak256(b"abc").hex()
          == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
          "abc")
    # Rate boundary: 136 bytes fills one block exactly; 137 spills.
    a = keccak256(b"x" * 136)
    b = keccak256(b"x" * 137)
    check(len(a) == 32 and a != b, "block boundary inputs differ")
    check(keccak256(b"x" * 136) == a, "deterministic")
    check(CHAIN_ID == hashlib.sha256(b"transpeer/anchor/v1").digest(),
          "CHAIN_ID is SHA-256 of transpeer/anchor/v1")


def test_varint():
    from transpeer.anchor.varint import write_varint, read_varint
    print("varint")
    check(write_varint(0) == b"\x00", "0")
    check(write_varint(127) == b"\x7f", "127")
    check(write_varint(128) == b"\x80\x01", "128")
    check(write_varint(0x3F6) == b"\xf6\x07", "0x3F6")
    for v in (0, 1, 127, 128, 300, 0xFFFFFFFF0, 0x7FFFFFFFFFF):
        val, pos = read_varint(b"\xaa" + write_varint(v) + b"\xbb", 1)
        check(val == v and pos == 1 + len(write_varint(v)), f"round trip {v:#x}")


def test_blob():
    from transpeer.anchor.blob import (
        encode_blob, decode_blob, blob_hash, list_body, with_period,
        period_of, is_reserved, BlobError, UnknownBlobVersion,
        PERIOD_SECONDS, MAX_ENTRIES,
    )
    print("list blob")
    entries = [("203.0.114.5", 7337), ("8.8.8.8", 7337), ("8.8.8.8", 7000)]
    b = encode_blob("monero", 12345, entries)
    check(b[:4] == b"TPL1" and b[4] == 1, "magic and version")
    check(b[5] == 6 and b[6:12] == b"monero", "chain name")
    check(int.from_bytes(b[12:20], "little") == 12345, "period at 6+n")
    check(int.from_bytes(b[20:22], "little") == 3, "count at 14+n")
    check(b[22:28] == bytes([8, 8, 8, 8]) + (7000).to_bytes(2, "little"),
          "first entry is lowest (address, port)")
    check(len(b) == 16 + 6 + 6 * 3, "length")
    d = decode_blob(b)
    check(d.chain == "monero" and d.period == 12345, "decode header")
    check(d.entries == (("8.8.8.8", 7000), ("8.8.8.8", 7337), ("203.0.114.5", 7337)),
          "decode entries sorted")
    check(blob_hash(b) == hashlib.sha256(b).digest(), "hash is sha256")
    body = list_body(b)
    check(int.from_bytes(body[12:20], "little") == 0 and body[22:] == b[22:], "body zeroes period")
    check(with_period(body, 12345) == b, "with_period restores")
    check(list_body(with_period(body, 99)) == body, "body is period-invariant")
    check(period_of(1500 * 1000 + 1499) == 1000 and period_of(1500 * 1001) == 1001,
          "period_of floors unix/1500")
    check(PERIOD_SECONDS == 1500 and MAX_ENTRIES == 64, "constants")

    def raises(exc, fn, name):
        try:
            fn()
        except exc:
            check(True, name)
        except Exception as e:  # noqa: BLE001
            check(False, f"{name} (raised {e!r})")
        else:
            check(False, name)

    raises(BlobError, lambda: encode_blob("monero", 1, []), "reject empty list")
    raises(BlobError, lambda: encode_blob("monero", 1, [("8.8.8.8", 1)] * 2), "reject duplicate")
    raises(BlobError, lambda: encode_blob("monero", 1, [("10.1.2.3", 1)]), "reject RFC 1918")
    raises(BlobError, lambda: encode_blob("monero", 1, [("100.64.0.1", 1)]), "reject CGNAT")
    raises(BlobError, lambda: encode_blob("monero", 1, [("198.18.0.1", 1)]), "reject benchmarking")
    raises(BlobError, lambda: encode_blob("monero", 1, [("240.0.0.1", 1)]), "reject 240/4")
    raises(BlobError, lambda: encode_blob("monero", 1, [("0.1.2.3", 1)]), "reject 0/8")
    raises(BlobError, lambda: encode_blob("monero", 1, [("8.8.8.8", 0)]), "reject port 0")
    raises(BlobError, lambda: encode_blob("", 1, [("8.8.8.8", 1)]), "reject empty chain")
    many = [(f"8.8.{i // 256}.{i % 256}", 1) for i in range(65)]
    raises(BlobError, lambda: encode_blob("monero", 1, many), "reject 65 entries")
    check(len(decode_blob(encode_blob("monero", 1, many[:64])).entries) == 64, "64 entries ok")
    check(is_reserved("127.0.0.1") and is_reserved("224.0.0.1") and not is_reserved("1.1.1.1"),
          "is_reserved")
    # Decoder rejects non-canonical bytes.
    unsorted = b[:22] + b[28:34] + b[22:28] + b[34:]
    raises(BlobError, lambda: decode_blob(unsorted), "decode rejects unsorted")
    raises(BlobError, lambda: decode_blob(b + b"\x00"), "decode rejects trailing bytes")
    raises(BlobError, lambda: decode_blob(b[:-1]), "decode rejects truncation")
    raises(UnknownBlobVersion, lambda: decode_blob(b[:4] + b"\x02" + b[5:]), "unknown version")
    raises(BlobError, lambda: decode_blob(b"XXXX" + b[4:]), "bad magic")


def test_merkle():
    from transpeer.anchor.keccak import keccak256
    from transpeer.anchor.merkle import (
        merkle_tree, merkle_root, merkle_proof, verify_merkle_proof,
        position_from_path, aux_slot, find_aux_nonce,
        encode_tree_params, decode_tree_params, build_mm_tag,
        parse_tx_extra_mm_tag, MM_TAG,
    )
    print("merkle")
    # Same leaves as P2Pool tests/src/merkle_tests.cpp TEST(merkle, tree).
    leaves = [keccak256(f"data {i}".encode()) for i in range(10)]
    check(merkle_root([]) is None, "empty root is None")
    check(merkle_root(leaves[:1]) == leaves[0], "single leaf is its own root")
    check(merkle_root(leaves[:2]) == keccak256(leaves[0] + leaves[1]), "two leaves")
    # Six leaves: first step pairs from the end (H0,H1,H(H2|H3),H(H4|H5)).
    l6 = leaves[:6]
    t = merkle_tree(l6)
    check(t[1] == [l6[0], l6[1], keccak256(l6[2] + l6[3]), keccak256(l6[4] + l6[5])],
          "non-power-of-two first step")
    check(len(t) == 4 and len(t[-1]) == 1, "tree height for 6 leaves")
    for n in range(1, 11):
        hs = leaves[:n]
        tree = merkle_tree(hs)
        root = merkle_root(hs)
        ok = tree[-1][0] == root and tree[0] == hs
        for idx, leaf in enumerate(hs):
            pr = merkle_proof(tree, leaf)
            ok = ok and pr is not None
            proof, path = pr
            ok = ok and verify_merkle_proof(leaf, proof, path, root)
            ok = ok and position_from_path(n, path) == idx
            ok = ok and not verify_merkle_proof(leaves[9 - idx] if n < 10 else b"\0" * 32,
                                                 proof, path, root)
        check(ok, f"proofs verify and positions round-trip, {n} leaves")
    check(merkle_proof(merkle_tree(leaves[:4]), b"\1" * 32) is None, "proof of absent leaf")
    # get_aux_slot vectors from P2Pool TEST(merkle, aux_slot): zero id.
    zid = bytes(32)
    exp = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 1, 6: 0, 7: 5, 8: 0, 9: 6}
    check(all(aux_slot(zid, 0, n) == s for n, s in exp.items()), "aux_slot small n")
    check(aux_slot(zid, 0, 0xFFFFFFFF) == 2389612776, "aux_slot nonce 0, n max")
    check(aux_slot(zid, 1, 0xFFFFFFFF) == 1080669337, "aux_slot nonce 1, n max")
    ids = [hashlib.sha256(bytes([i])).digest() for i in range(4)]
    nonce = find_aux_nonce(ids)
    check(len({aux_slot(c, nonce, 4) for c in ids}) == 4, "find_aux_nonce gives distinct slots")
    # encode_merkle_tree_data vectors from P2Pool TEST(merkle, params).
    vec = [((1, 0), 0), ((1, 0xFFFFFFFF), 0xFFFFFFFF0), ((127, 0), 0x3F6),
           ((127, 0xFFFFFFFF), 0x3FFFFFFFFF6), ((256, 0), 0x7FF),
           ((256, 0xFFFFFFFF), 0x7FFFFFFFFFF)]
    check(all(encode_tree_params(*a) == v for a, v in vec), "encode_tree_params vectors")
    check(all(decode_tree_params(v) == a for a, v in vec), "decode_tree_params vectors")
    root = merkle_root(leaves[:3])
    tag = build_mm_tag(3, 7, root)
    check(tag[0] == MM_TAG and tag[1] == len(tag) - 2 and tag[-32:] == root, "tag layout")
    extra = b"\x01" + bytes(32) + b"\x02\x03\x00\x00\x00" + tag
    got = parse_tx_extra_mm_tag(extra)
    check(got is not None and (got.n_aux_chains, got.nonce, got.root) == (3, 7, root),
          "parse tag after pubkey and extra nonce")
    check(parse_tx_extra_mm_tag(b"\x01" + bytes(32)) is None, "no tag -> None")
    check(parse_tx_extra_mm_tag(b"\x01" + bytes(32) + b"\x04\x01" + bytes(32) + tag) is not None,
          "tag after additional pubkeys")
    check(parse_tx_extra_mm_tag(tag[:-1]) is None, "truncated tag -> None")


def test_monero_block():
    from transpeer.anchor.monero import parse_block_blob, build_block_blob
    from transpeer.anchor.merkle import build_mm_tag, parse_tx_extra_mm_tag
    print("monero block blob")
    tag = build_mm_tag(2, 5, b"\x42" * 32)
    extra = b"\x01" + bytes(32) + b"\x02\x04\x00\x00\x00\x00" + tag
    prev = b"\x11" * 32
    blob = build_block_blob(16, 16, 1_700_000_000, prev, 0xDEADBEEF, 3_000_000, extra,
                            tx_hashes=[b"\x22" * 32, b"\x33" * 32])
    h = parse_block_blob(blob)
    check((h.major, h.minor, h.timestamp) == (16, 16, 1_700_000_000), "header varints")
    check(h.prev_id == prev and h.nonce == 0xDEADBEEF, "prev_id and nonce")
    check(h.height == 3_000_000, "height from miner tx input")
    check(h.tx_extra == extra and h.n_tx_hashes == 2, "tx_extra and tx count")
    check(parse_tx_extra_mm_tag(h.tx_extra).root == b"\x42" * 32, "tag reachable")
    check(blob[-64:] == b"\x22" * 32 + b"\x33" * 32, "tx hashes at the end")
    try:
        parse_block_blob(blob[:40])
        check(False, "truncated blob raises")
    except ValueError:
        check(True, "truncated blob raises")


def test_blobdb():
    import tempfile
    from transpeer.anchor.blob import encode_blob, blob_hash, list_body
    from transpeer.anchor.blobdb import BlobDB, Commitment
    print("blob database")
    db = BlobDB()
    b1 = encode_blob("monero", 100, [("8.8.8.8", 7337), ("1.1.1.1", 7337)])
    b2 = encode_blob("monero", 101, [("8.8.8.8", 7337), ("1.1.1.1", 7337)])  # same body
    b3 = encode_blob("monero", 101, [("9.9.9.9", 7337)])
    c1 = Commitment(blob_hash(b1), "share", "venue-a", "share:1", "wallet-x", 1000, 5000)
    check(db.add(b1, c1, now=5001), "add first blob")
    check(not db.add(b1, Commitment(b"\0" * 32, "share", "v", "r", "p", 1, 1), now=5002),
          "reject commitment whose hash mismatches")
    check(not db.add(b1 + b"\x00", Commitment(blob_hash(b1 + b"\x00"), "share", "v", "r", "p", 1, 1), 5002),
          "reject non-canonical blob")
    c2 = Commitment(blob_hash(b2), "block", "", "3000000:aa", "wallet-x", 10 ** 9, 6000, (b"\x01" * 32,), 1)
    check(db.add(b2, c2, now=6001), "add reissue of same body")
    check(db.body_count() == 1 and db.blob_count() == 2 and db.commitment_count() == 2,
          "body stored once, two blobs, two commitments")
    check(db.get(blob_hash(b2)) == b2 and db.get(blob_hash(b1)) == b1, "reconstruct blobs from body+period")
    check(db.get(b"\x07" * 32) is None, "missing hash")
    c1b = Commitment(blob_hash(b1), "share", "venue-a", "share:2", "wallet-x", 1200, 5100)
    check(db.add(b1, c1b, now=5101) and len(db.commitments(blob_hash(b1))) == 2, "second commitment appended")
    check(db.add(b1, c1b, now=5102) and len(db.commitments(blob_hash(b1))) == 2, "duplicate commitment ignored")
    check(db.add(b3, Commitment(blob_hash(b3), "share", "venue-b", "share:9", "w2", 7, 7000), 7001), "third blob")
    idx = db.index_since(5500)
    check([h for h, _, _ in idx] == [blob_hash(b2), blob_hash(b3)], "index_since filters and orders by first_seen")
    check(db.index_since(0, limit=1)[0][0] == blob_hash(b1), "index limit")
    check(db.has_body_entry("1.1.1.1", 7337) and not db.has_body_entry("1.1.1.1", 1), "has_body_entry")
    check(db.entries_of(blob_hash(b3)) == (("9.9.9.9", 7337),), "entries_of")
    # Persistence round trip.
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "anchor_blobs.json"
        db.save(p)
        db2 = BlobDB.load(p)
        check(db2.blob_count() == 3 and db2.get(blob_hash(b2)) == b2, "save/load blobs")
        check(db2.commitments(blob_hash(b2))[0] == c2, "save/load commitment with proof")
        check(BlobDB.load(Path(d) / "missing.json").blob_count() == 0, "load missing file -> empty")


def test_weight():
    from transpeer.anchor import CHAIN_ID
    from transpeer.anchor.blob import encode_blob, blob_hash
    from transpeer.anchor.blobdb import BlobDB, Commitment
    from transpeer.anchor.weight import (
        Share, canonical_window, blob_weights, transpeer_weights,
        publisher_weights, coverage, bootstrapped, BOOTSTRAP_COVERAGE,
    )
    print("weighting and coverage")
    ba = encode_blob("monero", 1, [("1.1.1.1", 7337), ("2.2.2.2", 7337)])
    bb = encode_blob("monero", 1, [("2.2.2.2", 7337), ("3.3.3.3", 7337)])
    ha, hb = blob_hash(ba), blob_hash(bb)
    db = BlobDB()
    db.add(ba, Commitment(ha, "share", "v", "s1", "wa", 1, 1), 1)
    db.add(bb, Commitment(hb, "share", "v", "s2", "wb", 1, 1), 1)

    def mk(i, parent, diff, aux, wallet="w"):
        return Share(bytes([i]) * 32, "v", i, parent, diff, 1000 + i, wallet, aux)
    s = {}
    s[bytes([1]) * 32] = mk(1, bytes(32), 100, {CHAIN_ID: ha}, "wa")
    s[bytes([2]) * 32] = mk(2, bytes([1]) * 32, 200, {CHAIN_ID: hb}, "wb")
    s[bytes([3]) * 32] = mk(3, bytes([2]) * 32, 300, {}, "wc")
    s[bytes([4]) * 32] = mk(4, bytes([3]) * 32, 400, {CHAIN_ID: ha}, "wa")
    s[bytes([9]) * 32] = mk(9, bytes([2]) * 32, 9999, {CHAIN_ID: hb}, "wb")  # off-fork
    win = canonical_window(s, bytes([4]) * 32, window=3)
    check([x.height for x in win] == [4, 3, 2], "walk parents from tip, window 3")
    check([x.height for x in canonical_window(s, bytes([4]) * 32, 10)] == [4, 3, 2, 1],
          "walk stops at unknown parent")
    bw = blob_weights(win)
    check(bw == {ha: 400, hb: 200}, "blob weight sums share difficulty on the canonical fork only")
    tw = transpeer_weights(bw, db)
    check(tw == {("1.1.1.1", 7337): 400, ("2.2.2.2", 7337): 600, ("3.3.3.3", 7337): 200},
          "transpeer weight sums over blobs listing it")
    check(publisher_weights(win) == {"wa": 400, "wb": 200}, "publisher weights (diagnostic)")
    check(blob_weights(win, chain_id=b"\x00" * 32) == {}, "other chain id contributes nothing")
    check(coverage(10, 5) == 0.5 and coverage(0, 0) == 0.0, "coverage ratio")
    check(bootstrapped(10, 5) and not bootstrapped(10, 4) and BOOTSTRAP_COVERAGE == 0.5,
          "bootstrapped at one half")


def main():
    test_keccak()
    test_varint()
    test_blob()
    test_merkle()
    test_monero_block()
    test_blobdb()
    test_weight()
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
