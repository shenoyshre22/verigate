"""Builds the decision engine Context from campus records in DynamoDB. Read-only.

Tables (env): IDENTITIES_TABLE (GSI "by-card"), AUTHORIZATION_TABLE, REVOCATIONS_TABLE.
Every ambiguity resolves towards denial: unknown or duplicated cards give no identity,
a missing or old updated_at marks records as stale, and grants outside their window do not count.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from boto3.dynamodb.conditions import Key

from .engine import Context

DEFAULT_FRESHNESS_MINUTES = 1440
DEFAULT_SENSITIVE_ROOMS = "EXAMHALL,CHEMLAB"
SCHEDULE_PREFIX = "ROOM#{room}#"
PASS_PREFIX = "PASS#{room}#"
CLOCK_SKEW = timedelta(minutes=5)


def parse_ts(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (with Z or offset) to an aware UTC datetime, or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def normalize_room(room_id: str) -> str:
    return room_id.strip().upper()


def sensitive_rooms() -> frozenset[str]:
    raw = os.environ.get("SENSITIVE_ROOMS", DEFAULT_SENSITIVE_ROOMS)
    return frozenset(normalize_room(r) for r in raw.split(",") if r.strip())


def freshness_window() -> timedelta:
    try:
        minutes = int(os.environ.get("FRESHNESS_MINUTES", DEFAULT_FRESHNESS_MINUTES))
    except ValueError:
        minutes = DEFAULT_FRESHNESS_MINUTES
    return timedelta(minutes=max(minutes, 0))


@dataclass
class LoadedContext:
    context: Context
    person_id: Optional[str] = None        # identity the decision is about
    card_person_id: Optional[str] = None   # owner of the presented card (feeds Evidence.rfid_person_id)
    grants: list = field(default_factory=list)


class ContextLoader:
    """Reads identity, grants and revocations. Tables can be injected for tests."""

    def __init__(self, identities=None, authorization=None, revocations=None):
        self._identities = identities
        self._authorization = authorization
        self._revocations = revocations

    @staticmethod
    def _table(env_name: str):
        import boto3

        name = os.environ[env_name]  # KeyError -> caller fails closed
        return boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1")).Table(name)

    @property
    def identities(self):
        if self._identities is None:
            self._identities = self._table("IDENTITIES_TABLE")
        return self._identities

    @property
    def authorization(self):
        if self._authorization is None:
            self._authorization = self._table("AUTHORIZATION_TABLE")
        return self._authorization

    @property
    def revocations(self):
        if self._revocations is None:
            self._revocations = self._table("REVOCATIONS_TABLE")
        return self._revocations

    # --- individual lookups -------------------------------------------------
    def identity_by_person(self, person_id: str) -> Optional[dict]:
        return self.identities.get_item(Key={"person_id": person_id}, ConsistentRead=True).get("Item")

    def identity_by_card(self, card_id: str) -> Optional[dict]:
        items = self.identities.query(
            IndexName="by-card", KeyConditionExpression=Key("rfid_card_id").eq(card_id)
        ).get("Items", [])
        return items[0] if len(items) == 1 else None  # unknown or duplicated card -> no identity

    def revocation(self, subject_id: str) -> Optional[dict]:
        return self.revocations.get_item(Key={"subject_id": subject_id}, ConsistentRead=True).get("Item")

    def active_grants(self, person_id: str, prefix: str, now: datetime) -> list[dict]:
        items = self.authorization.query(
            KeyConditionExpression=Key("person_id").eq(person_id) & Key("grant_key").begins_with(prefix)
        ).get("Items", [])
        active = []
        for g in items:
            start, end = parse_ts(g.get("valid_from")), parse_ts(g.get("valid_to"))
            if start and end and start <= now <= end:
                active.append(g)
        return active

    # --- full context -------------------------------------------------------
    def load(
        self,
        *,
        room_id: str,
        person_id: Optional[str] = None,
        rfid_card_id: Optional[str] = None,
        online: bool = True,
        now: Optional[datetime] = None,
    ) -> LoadedContext:
        now = now or datetime.now(timezone.utc)
        room = normalize_room(room_id)

        card_owner = None
        card_identity = None
        if rfid_card_id:
            card_identity = self.identity_by_card(rfid_card_id)
            card_owner = card_identity.get("person_id") if card_identity else None

        if rfid_card_id and card_identity is None:
            person = None  # a presented card we cannot resolve never yields an identity
        elif person_id:
            person = self.identity_by_person(person_id)
        else:
            person = card_identity

        pid = person.get("person_id") if person else None
        revoked = any(self.revocation(s) is not None for s in (pid, rfid_card_id) if s)

        schedule = self.active_grants(pid, SCHEDULE_PREFIX.format(room=room), now) if pid else []
        passes = self.active_grants(pid, PASS_PREFIX.format(room=room), now) if pid else []

        ctx = Context(
            person=person,
            revoked=revoked,
            schedule_ok=bool(schedule),
            temp_pass_valid=bool(passes),
            room_sensitive=room in sensitive_rooms(),
            records_fresh=self._fresh(person, schedule + passes, now),
            online=online,
        )
        return LoadedContext(context=ctx, person_id=pid, card_person_id=card_owner, grants=schedule + passes)

    @staticmethod
    def _fresh(person: Optional[dict], grants: list[dict], now: datetime) -> bool:
        """Identity must carry a recent updated_at; grants are checked when they carry one."""
        if person is None:
            return True  # nothing to be stale; the engine denies unknown identities anyway
        window = freshness_window()

        def ok(ts: Any) -> bool:
            dt = parse_ts(ts)
            if dt is None:
                return False
            age = now - dt
            return -CLOCK_SKEW <= age <= window  # far-future timestamps are as suspect as old ones

        if not ok(person.get("updated_at")):
            return False
        return all(ok(g["updated_at"]) for g in grants if g.get("updated_at"))
