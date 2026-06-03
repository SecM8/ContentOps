# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Post-apply verification helpers shared by every write handler.

After a successful PUT/POST the handler GETs the resource again and
compares a stable hash of the relevant remote fields against the hash
of the body we sent. A mismatch is surfaced as a per-asset failure
(`verified=False`) rather than a hard crash so the rest of the apply
batch keeps running.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _get_path(body: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted path inside a nested dict.

    Returns ``None`` when any segment is missing or non-dict, so the
    hash is stable across "absent" vs. "null" — both feed the same
    canonical JSON.
    """
    cur: Any = body
    for segment in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(segment)
    return cur


def compute_content_hash(body: dict[str, Any], fields: list[str]) -> str:
    """SHA-256 over the canonical-JSON projection of ``fields`` from ``body``.

    The projection uses sorted keys and tight separators so the digest
    is stable regardless of dict ordering or whitespace differences
    introduced by httpx / the remote API.
    """
    subset = {field: _get_path(body, field) for field in fields}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_projection_hash(projection: dict[str, Any]) -> str:
    """SHA-256 over the canonical-JSON form of an arbitrary pre-built projection.

    Used by handlers that need a derived hash (e.g. counts and sorted
    type lists) instead of a raw dotted-path field selection. The caller
    is responsible for building a projection that is stable under server
    normalization (sorted lists, no positional indexing, no fields the
    server is known to mutate).
    """
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_mismatch_error(sent_hash: str, got_hash: str) -> str:
    """Format a consistent per-asset error for hash mismatch."""
    return f"post-apply hash mismatch: sent={sent_hash[:8]}... got={got_hash[:8]}..."


ETAG_CONFLICT_MESSAGE = (
    "Remote etag changed since plan; rerun contentops plan and resolve drift"
)


def extract_etag(remote: dict | None) -> str | None:
    """Return the etag for ``remote``, handling both ARM placements.

    Sentinel sub-resources sometimes expose the etag at the top level
    (``remote["etag"]``) and sometimes inside the properties bag
    (``remote["properties"]["etag"]``) depending on the API version.
    Callers used to repeat ``existing.get("etag") or existing.get(
    "properties", {}).get("etag")`` inline, and one handler
    (``sentinel_data_connector``) only checked the top level — meaning
    its PUTs silently dropped ``If-Match`` whenever ARM nested the etag.
    Centralising the lookup eliminates that asymmetry.
    """
    if not remote:
        return None
    top = remote.get("etag")
    if top:
        return str(top)
    props = remote.get("properties")
    if isinstance(props, dict):
        nested = props.get("etag")
        if nested:
            return str(nested)
    return None
