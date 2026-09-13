"""The aux-chain JSON-RPC server P2Pool polls (spec §4.2). Three
methods, verified against p2pool v4.18 merge_mining_client_json_rpc.cpp:
P2Pool polls every 500 ms, treats an empty result or an unchanged
aux_hash as "no change", drops the chain after 1800 s without a hash
change, and may submit a solution for any of its last 8 aux hashes."""

import json
import logging
import time

from aiohttp import web

from . import CHAIN_ID
from .blobdb import BlobDB, Commitment
from .merkle import parse_tx_extra_mm_tag, verify_merkle_proof
from .monero import parse_block_blob
from .publisher import Publisher, Solution

log = logging.getLogger("transpeer.anchor.auxrpc")


class AuxRpcServer:
    def __init__(self, publisher: Publisher, db: BlobDB, aux_diff: int, clock=time.time):
        self.publisher = publisher
        self.db = db
        self.aux_diff = aux_diff
        self.clock = clock
        self.stats = {"get_aux_block": 0, "changed": 0, "submit": 0, "submit_rejected": 0}

    # -- dispatch -----------------------------------------------------------

    def handle(self, req: dict) -> dict:
        rid = req.get("id", "0")
        method = req.get("method")
        params = req.get("params") or {}
        try:
            if method == "merge_mining_get_chain_id":
                result = {"chain_id": CHAIN_ID.hex(), "ticker": "TPL"}
            elif method == "merge_mining_get_aux_block":
                result = self._get_aux_block(params)
            elif method == "merge_mining_submit_solution":
                result = self._submit_solution(params)
            else:
                return {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32601, "message": "method not found"}}
        except _Reject as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -1, "message": str(e)}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _get_aux_block(self, params: dict) -> dict:
        self.stats["get_aux_block"] += 1
        addr = params.get("address")
        if isinstance(addr, str) and addr:
            self.publisher.address = addr
        self.publisher.refresh()
        cur = self.publisher.current()
        if cur is None:
            return {}
        h, blob = cur
        if params.get("aux_hash") == h.hex():
            return {}
        self.stats["changed"] += 1
        return {"aux_blob": blob.hex(), "aux_diff": self.aux_diff, "aux_hash": h.hex()}

    def _submit_solution(self, params: dict) -> dict:
        self.stats["submit"] += 1
        try:
            aux_hash = bytes.fromhex(params["aux_hash"])
            aux_blob = bytes.fromhex(params["aux_blob"])
            blob = bytes.fromhex(params["blob"])
            proof = tuple(bytes.fromhex(p) for p in params["merkle_proof"])
            path = int(params["path"])
            seed_hash = bytes.fromhex(params.get("seed_hash", ""))
        except (KeyError, ValueError, TypeError) as e:
            return self._reject(f"malformed params: {e}")
        if self.publisher.lookup(aux_hash) != aux_blob:
            return self._reject("unknown aux_hash or blob mismatch")
        try:
            head = parse_block_blob(blob)
        except ValueError as e:
            return self._reject(f"bad block blob: {e}")
        tag = parse_tx_extra_mm_tag(head.tx_extra)
        if tag is None:
            return self._reject("no merge-mining tag in coinbase")
        if not verify_merkle_proof(aux_hash, list(proof), path, tag.root):
            return self._reject("merkle proof does not reach the tag root")
        now = int(self.clock())
        sol = Solution(aux_hash, head.height, head.prev_id, head.timestamp, tag.root,
                       proof, path, seed_hash, self.publisher.address, now)
        self.publisher.record_solution(sol)
        self.db.add(aux_blob, Commitment(
            aux_hash, "template", "local",
            f"template:{head.height}:{head.prev_id.hex()}",
            self.publisher.address, self.aux_diff, head.timestamp, proof, path,
        ), now)
        log.info("aux solution accepted at height %d for %s", head.height, aux_hash.hex()[:16])
        return {"status": "accepted"}

    def _reject(self, reason: str):
        self.stats["submit_rejected"] += 1
        log.warning("aux solution rejected: %s", reason)
        raise _Reject(reason)

    # -- HTTP ---------------------------------------------------------------

    async def handle_http(self, request: web.Request) -> web.Response:
        try:
            req = json.loads(await request.read())
            if not isinstance(req, dict):
                raise ValueError("not an object")
        except ValueError:
            return web.json_response({"jsonrpc": "2.0", "id": "0",
                                      "error": {"code": -32700, "message": "parse error"}})
        return web.json_response(self.handle(req))

    def create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/", self.handle_http)
        app.router.add_post("/json_rpc", self.handle_http)
        return app


class _Reject(Exception):
    pass
