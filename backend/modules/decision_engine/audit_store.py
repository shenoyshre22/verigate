"""Append-only, hash-chained audit log in DynamoDB (AUDIT_TABLE, keys day / ts_attempt).

A single HEAD item (day="CHAIN", ts_attempt="HEAD") holds the latest hash and sequence number.
Appending first moves HEAD with a conditional write, so two concurrent Lambdas can never both
chain onto the same previous hash; the loser re-reads HEAD and retries. Records carry `seq`,
so offline decisions synced later (with older timestamps) still verify in chain order.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Iterable

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from .audit import GENESIS, record_hash, verify

HEAD_KEY = {"day": "CHAIN", "ts_attempt": "HEAD"}
MARKER_PARTITIONS = ("CHAIN", "OFFLINE-SYNC", "LIVENESS-SESSION")
RETENTION_DAYS = 30
MAX_RETRIES = 5


class AuditUnavailable(RuntimeError):
    """The audit record could not be written."""


def canonical_number(value: Any) -> Decimal:
    """The form DynamoDB returns a number in: no trailing zeros, no exponent (97.0 -> 97, 1.50 -> 1.5).
    Hashing this form means a record read back from DynamoDB hashes exactly as it did when written."""
    d = value if isinstance(value, Decimal) else Decimal(str(value))
    if d == d.to_integral_value():
        return Decimal(int(d))
    return Decimal(format(d.normalize(), "f"))


def ddb_safe(value: Any) -> Any:
    """DynamoDB-storable copy with numbers in canonical form (see canonical_number)."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float, Decimal)):
        return canonical_number(value)
    if isinstance(value, dict):
        return {k: ddb_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [ddb_safe(v) for v in value]
    return str(value)


def _is_conditional_failure(e: ClientError) -> bool:
    return e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


class AuditLog:
    def __init__(self, table=None):
        self._table = table

    @property
    def table(self):
        if self._table is None:
            import boto3

            region = os.environ.get("AWS_REGION", "us-east-1")
            self._table = boto3.resource("dynamodb", region_name=region).Table(os.environ["AUDIT_TABLE"])
        return self._table

    def append(self, record: dict, *, day: str, ts_attempt: str, now: datetime) -> dict:
        body = ddb_safe({
            **record,
            "day": day,
            "ts_attempt": ts_attempt,
            "expires_at": int((now + timedelta(days=RETENTION_DAYS)).timestamp()),
        })
        try:
            for _ in range(MAX_RETRIES):
                head = self.table.get_item(Key=HEAD_KEY, ConsistentRead=True).get("Item")
                prev = head["hash"] if head else GENESIS
                seq = int(head["seq"]) + 1 if head else 1
                item = {**body, "seq": Decimal(seq)}
                h = record_hash(prev, item)
                cond = Attr("hash").eq(prev) if head else Attr("hash").not_exists()
                try:
                    self.table.put_item(
                        Item={**HEAD_KEY, "hash": h, "seq": Decimal(seq), "day_ref": day, "ts_attempt_ref": ts_attempt},
                        ConditionExpression=cond,
                    )
                except ClientError as e:
                    if _is_conditional_failure(e):
                        continue  # another writer advanced the chain; retry on the new head
                    raise
                final = {**item, "prev_hash": prev, "hash": h}
                self.table.put_item(Item=final, ConditionExpression=Attr("ts_attempt").not_exists())
                return final
        except ClientError as e:
            raise AuditUnavailable(str(e)) from e
        raise AuditUnavailable("audit chain is busy; retries exhausted")

    def _claim(self, partition: str, key: str, now: datetime, condition) -> bool:
        try:
            self.table.put_item(
                Item=ddb_safe({
                    "day": partition, "ts_attempt": key, "status": "pending",
                    "expires_at": int((now + timedelta(days=RETENTION_DAYS)).timestamp()),
                }),
                ConditionExpression=condition,
            )
            return True
        except ClientError as e:
            if _is_conditional_failure(e):
                return False
            raise AuditUnavailable(str(e)) from e

    # One-time-use markers for liveness sessions: day="LIVENESS-SESSION", ts_attempt=<session_id>.
    def claim_liveness_session(self, session_id: str, now: datetime) -> bool:
        """True the first time a session id is presented; False on any reuse (replay)."""
        return self._claim("LIVENESS-SESSION", session_id, now, Attr("ts_attempt").not_exists())

    # Dedup markers for offline sync: day="OFFLINE-SYNC", ts_attempt=<attempt_id>.
    def claim_offline(self, attempt_id: str, now: datetime) -> bool:
        """True if this attempt id was not synced before (marker written or still pending)."""
        return self._claim("OFFLINE-SYNC", attempt_id, now,
                           Attr("ts_attempt").not_exists() | Attr("status").eq("pending"))

    def mark_offline_synced(self, attempt_id: str, now: datetime, ts_attempt: str) -> None:
        self.table.put_item(Item=ddb_safe({
            "day": "OFFLINE-SYNC", "ts_attempt": attempt_id, "status": "synced", "record": ts_attempt,
            "expires_at": int((now + timedelta(days=RETENTION_DAYS)).timestamp()),
        }))


def verify_items(items: Iterable[dict], from_seq: int = 1) -> bool:
    """Verify audit records read back from DynamoDB in chain (seq) order, starting at from_seq.
    Also fails on a gap in seq, i.e. a record deleted from the middle of the checked range."""
    records = sorted((ddb_safe(i) for i in items
                      if "seq" in i and i.get("day") not in MARKER_PARTITIONS and int(i["seq"]) >= from_seq),
                     key=lambda i: int(i["seq"]))
    if not records:
        return True
    seqs = [int(r["seq"]) for r in records]
    if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        return False
    return verify(records, prev_hash=records[0]["prev_hash"])
