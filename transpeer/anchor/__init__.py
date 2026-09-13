"""Chain-anchored publication of transpeer lists.

Spec: docs/spec-chain-anchored-publication.md. Everything here is
behind --anchor-publish (and, in a later slice, --anchor-read).
"""

import hashlib

# Spec §4.2: the merge-mined chain id the sidecar reports to P2Pool.
CHAIN_ID = hashlib.sha256(b"transpeer/anchor/v1").digest()
