"""Tamper-evident audit chain: each record stores the hash of the previous one."""
from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def record_hash(prev_hash: str, record: dict) -> str:
    """SHA-256 over the previous hash plus the record in canonical JSON."""
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def chain(records: list[dict], prev_hash: str = GENESIS) -> list[dict]:
    """Return copies of records with prev_hash and hash fields added."""
    out = []
    for r in records:
        h = record_hash(prev_hash, r)
        out.append({**r, "prev_hash": prev_hash, "hash": h})
        prev_hash = h
    return out


def verify(chained: list[dict], prev_hash: str = GENESIS) -> bool:
    """True if no record was changed, removed or reordered."""
    for r in chained:
        body = {k: v for k, v in r.items() if k not in ("prev_hash", "hash")}
        if r.get("prev_hash") != prev_hash or record_hash(prev_hash, body) != r.get("hash"):
            return False
        prev_hash = r["hash"]
    return True
