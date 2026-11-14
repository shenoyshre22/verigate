"""Exactly what a kiosk may cache for offline operation, and when that cache is too old.

Allowed: revoked credential ids (card ids / person ids), the list version and when it was fetched.
Never cached: face images, face vectors, fingerprint templates, names, schedules or grants.
Offline, the engine only opens normal rooms on card + on-device fingerprint (see engine._offline),
denies sensitive rooms outright, and denies everything once this cache is stale.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from .context_loader import CLOCK_SKEW, normalize_room, parse_ts, sensitive_rooms
from .engine import Context

CACHEABLE_FIELDS = frozenset({"revoked_ids", "list_version", "fetched_at"})
# Fields a queued offline decision may carry to POST /decision/offline-sync.
QUEUE_FIELDS = frozenset({"attempt_id", "room_id", "person_id", "rfid_card_id", "decision", "decided_at", "reasons"})
DEFAULT_MAX_AGE_MINUTES = 15


def max_age() -> timedelta:
    try:
        minutes = int(os.environ.get("OFFLINE_CACHE_MAX_AGE_MINUTES", DEFAULT_MAX_AGE_MINUTES))
    except ValueError:
        minutes = DEFAULT_MAX_AGE_MINUTES
    return timedelta(minutes=max(minutes, 0))


@dataclass(frozen=True)
class OfflineCache:
    revoked_ids: frozenset
    list_version: int
    fetched_at: datetime

    @classmethod
    def from_dict(cls, data: dict) -> "OfflineCache":
        extra = set(data) - CACHEABLE_FIELDS
        if extra:
            raise ValueError(f"fields not allowed in the offline cache: {sorted(extra)}")
        fetched = parse_ts(data.get("fetched_at"))
        if fetched is None:
            raise ValueError("fetched_at is required")
        return cls(frozenset(str(i) for i in data.get("revoked_ids", [])), int(data["list_version"]), fetched)

    @classmethod
    def build(cls, revoked_ids: Iterable[str], list_version: int, now: Optional[datetime] = None) -> "OfflineCache":
        return cls(frozenset(revoked_ids), list_version, now or datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "revoked_ids": sorted(self.revoked_ids),
            "list_version": self.list_version,
            "fetched_at": self.fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def is_stale(self, now: Optional[datetime] = None, limit: Optional[timedelta] = None) -> bool:
        """Stale when older than the limit, or dated in the future (clock tampering)."""
        age = (now or datetime.now(timezone.utc)) - self.fetched_at
        return age < -CLOCK_SKEW or age > (limit if limit is not None else max_age())

    def is_revoked(self, *ids: Optional[str]) -> bool:
        return any(i in self.revoked_ids for i in ids if i)

    def offline_context(self, *, room_id: str, person_id: Optional[str] = None,
                        rfid_card_id: Optional[str] = None, now: Optional[datetime] = None) -> Context:
        return Context(
            person=None,
            revoked=self.is_revoked(person_id, rfid_card_id),
            room_sensitive=normalize_room(room_id) in sensitive_rooms(),
            records_fresh=not self.is_stale(now),
            online=False,
        )
