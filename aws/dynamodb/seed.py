"""Seed SYNTHETIC demo records. Run only after deployment is approved.

python aws/dynamodb/seed.py --stage dev
"""
import argparse
import time
from datetime import datetime, timedelta, timezone

import boto3

p = argparse.ArgumentParser()
p.add_argument("--stage", default="dev")
p.add_argument("--region", default="us-east-1")
a = p.parse_args()
db = boto3.resource("dynamodb", region_name=a.region)
now = datetime.now(timezone.utc)
iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
day_end = int((now + timedelta(days=1)).timestamp())

identities = [
    {"person_id": "P001", "name": "Test Student A", "role": "student", "status": "active",
     "rfid_card_id": "CARD-A1", "face_ref": "P001", "source": "registrar", "version": 3, "updated_at": iso(now)},
    {"person_id": "P002", "name": "Test Student B", "role": "student", "status": "suspended",
     "rfid_card_id": "CARD-B2", "face_ref": "P002", "source": "disciplinary_office", "version": 5, "updated_at": iso(now)},
    {"person_id": "P003", "name": "Test Staff C", "role": "staff", "status": "active",
     "rfid_card_id": "CARD-C3", "face_ref": "P003", "source": "hr", "version": 1, "updated_at": iso(now)},
]
grants = [
    {"person_id": "P001", "grant_key": f"ROOM#LAB3#{iso(now - timedelta(hours=1))}",
     "room_id": "LAB3", "valid_from": iso(now - timedelta(hours=1)), "valid_to": iso(now + timedelta(hours=3)),
     "type": "exam_schedule", "source": "exam_office", "version": 2, "expires_at": day_end},
    {"person_id": "P003", "grant_key": f"PASS#LAB1#{iso(now)}",
     "room_id": "LAB1", "valid_from": iso(now), "valid_to": iso(now + timedelta(minutes=90)),
     "type": "temporary_pass", "issued_by": "invigilator-01", "source": "invigilator", "version": 1, "expires_at": day_end},
]
revocations = [
    {"subject_id": "CARD-X9", "reason": "card reported lost", "revoked_at": iso(now), "version": 1},
]

t = lambda n: db.Table(f"verigate-{a.stage}-{n}")
for i in identities: t("identities").put_item(Item=i)
for g in grants: t("authorization").put_item(Item=g)
for r in revocations: t("revocations").put_item(Item=r)
print("Seeded", len(identities), "identities,", len(grants), "grants,", len(revocations), "revocations (synthetic).")
