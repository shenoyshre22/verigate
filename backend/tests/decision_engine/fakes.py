"""In-memory stand-in for a boto3 DynamoDB Table. No AWS calls.

Evaluates the real boto3 condition objects (Key/Attr) used by the code under test, so key
conditions, begins_with and conditional writes behave like DynamoDB for these access patterns.
"""
from __future__ import annotations

import copy
from decimal import Decimal

from botocore.exceptions import ClientError


def _eval(cond, item: dict) -> bool:
    expr = cond.get_expression()
    op, vals = expr["operator"], expr["values"]
    if op == "AND":
        return _eval(vals[0], item) and _eval(vals[1], item)
    if op == "OR":
        return _eval(vals[0], item) or _eval(vals[1], item)
    name = vals[0].name
    if op == "=":
        return name in item and item[name] == vals[1]
    if op == "begins_with":
        return isinstance(item.get(name), str) and item[name].startswith(vals[1])
    if op == "attribute_not_exists":
        return name not in item
    if op == "attribute_exists":
        return name in item
    raise NotImplementedError(op)


def _as_dynamodb_returns(value):
    """DynamoDB does not keep a number's formatting: Decimal('97.0') comes back as Decimal('97')."""
    if isinstance(value, Decimal):
        return Decimal(int(value)) if value == value.to_integral_value() else Decimal(format(value.normalize(), "f"))
    if isinstance(value, dict):
        return {k: _as_dynamodb_returns(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_as_dynamodb_returns(v) for v in value]
    return value


def _conditional_failure(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}}, op)


class FakeTable:
    def __init__(self, hash_key: str, range_key: str | None = None, indexes: dict | None = None):
        self.hash_key, self.range_key = hash_key, range_key
        self.indexes = indexes or {}
        self.items: dict[tuple, dict] = {}
        self.calls: list[str] = []

    def _key(self, item: dict) -> tuple:
        return (item[self.hash_key], item.get(self.range_key) if self.range_key else None)

    def get_item(self, Key, ConsistentRead=False):  # noqa: N803 - boto3 casing
        self.calls.append("get_item")
        item = self.items.get(self._key(Key))
        return {"Item": copy.deepcopy(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None):  # noqa: N803
        self.calls.append("put_item")
        existing = self.items.get(self._key(Item), {})
        if ConditionExpression is not None and not _eval(ConditionExpression, existing):
            raise _conditional_failure("PutItem")
        self.items[self._key(Item)] = _as_dynamodb_returns(copy.deepcopy(Item))
        return {}

    def query(self, KeyConditionExpression, IndexName=None, ScanIndexForward=True, Limit=None):  # noqa: N803
        self.calls.append("query")
        if IndexName is not None and IndexName not in self.indexes:
            raise ClientError({"Error": {"Code": "ValidationException", "Message": "no index"}}, "Query")
        out = [copy.deepcopy(i) for i in self.items.values() if _eval(KeyConditionExpression, i)]
        sort = self.range_key if IndexName is None else self.indexes[IndexName]
        if sort:
            out.sort(key=lambda i: str(i.get(sort, "")), reverse=not ScanIndexForward)
        return {"Items": out[:Limit] if Limit else out}


class BrokenTable:
    """Every call fails, as if DynamoDB were unreachable or access were denied."""

    def __getattr__(self, name):
        def fail(*a, **kw):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, name)
        return fail


class FakeRekognition:
    """Stands in for boto3's rekognition client: get_face_liveness_session_results only."""

    def __init__(self, sessions: dict | None = None):
        self.sessions = sessions or {}  # session_id -> response dict or Exception
        self.calls: list[str] = []

    def get_face_liveness_session_results(self, SessionId):  # noqa: N803
        self.calls.append(SessionId)
        r = self.sessions.get(SessionId)
        if r is None:
            raise ClientError({"Error": {"Code": "SessionNotFoundException", "Message": "not found"}},
                              "GetFaceLivenessSessionResults")
        if isinstance(r, Exception):
            raise r
        return copy.deepcopy(r)


def campus_tables():
    return {
        "identities": FakeTable("person_id", indexes={"by-card": None}),
        "authorization": FakeTable("person_id", "grant_key"),
        "revocations": FakeTable("subject_id"),
        "audit": FakeTable("day", "ts_attempt"),
    }
