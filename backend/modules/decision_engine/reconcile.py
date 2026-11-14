"""Campus-record reconciliation: which source decides a person's status.

Several offices can assert a status for the same person (registrar, HR, disciplinary office ...).
1. Per source, only its latest record counts (highest version, then latest updated_at).
2. The most authoritative sources present decide (SOURCE_AUTHORITY).
3. If equally authoritative sources disagree, the conflict is unresolvable here: the engine asks
   for manual verification, or denies outright in a sensitive room. It never guesses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Higher wins. Unknown sources rank 0 and are outranked by any known office.
SOURCE_AUTHORITY = {
    "disciplinary_office": 3,
    "security_office": 3,
    "registrar": 2,
    "hr": 2,
    "exam_office": 1,
    "invigilator": 1,
}


@dataclass(frozen=True)
class Reconciled:
    status: Optional[str]        # None when unresolved or no records
    sources: tuple = ()          # the source(s) that decided, or that conflict
    conflict: bool = False
    detail: str = ""
    considered: dict = field(default_factory=dict)  # source -> (status, version) actually used


def _authority(source: str) -> int:
    return SOURCE_AUTHORITY.get(source, 0)


def reconcile_status(records: list[dict]) -> Reconciled:
    latest: dict[str, tuple] = {}
    for r in records or []:
        src, status = r.get("source"), r.get("status")
        if not src or not status:
            continue
        rank = (int(r.get("version") or 0), str(r.get("updated_at") or ""))
        if src not in latest or rank > latest[src][0]:
            latest[src] = (rank, r)
    if not latest:
        return Reconciled(None, detail="no status records")

    considered = {s: (r["status"], k[0]) for s, (k, r) in latest.items()}
    top = max(_authority(s) for s in latest)
    deciding = {s: considered[s][0] for s in sorted(latest) if _authority(s) == top}
    statuses = set(deciding.values())
    if len(statuses) == 1:
        status = statuses.pop()
        return Reconciled(status, tuple(deciding), False, f"{status} per {', '.join(deciding)}", considered)
    detail = "equally authoritative sources disagree: " + ", ".join(f"{s}={v}" for s, v in deciding.items())
    return Reconciled(None, tuple(deciding), True, detail, considered)


def reconcile_identity(person: Optional[dict]) -> tuple[Optional[dict], Optional[Reconciled]]:
    """Return a copy of the identity with its reconciled status, plus the reconciliation result.
    Records without `status_records` are treated as one assertion from their own `source`."""
    if person is None:
        return None, None
    records = person.get("status_records")
    if not records:
        records = [{"source": person.get("source") or "unspecified", "status": person.get("status"),
                    "version": person.get("version"), "updated_at": person.get("updated_at")}]
    result = reconcile_status(records)
    return {**person, "status": result.status}, result
