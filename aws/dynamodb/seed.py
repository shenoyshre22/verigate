"""Seed SYNTHETIC demo records. Run only after deployment is approved.

python aws/dynamodb/seed.py --stage dev                 # everything below
python aws/dynamodb/seed.py --stage dev --refresh-sync  # only mark the campus revocation feed as refreshed now

build(now) is pure (no AWS) so the tests load exactly the records that are seeded live.
"""
import argparse
from datetime import datetime, timedelta, timezone


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def build(now):
    day_end = int((now + timedelta(days=1)).timestamp())
    h = lambda n: timedelta(hours=n)
    m = lambda n: timedelta(minutes=n)

    def person(pid, status="active", source="registrar", **extra):
        return {"person_id": pid, "name": f"Scenario {pid}", "role": "student", "status": status,
                "rfid_card_id": f"CARD-{pid}", "face_ref": pid, "source": source, "version": 1,
                "updated_at": iso(now), **extra}

    def grant(pid, prefix, room, start, end, kind, source, **extra):
        return {"person_id": pid, "grant_key": f"{prefix}#{room}#{iso(start)}", "room_id": room,
                "valid_from": iso(start), "valid_to": iso(end), "type": kind, "source": source,
                "version": 1, "expires_at": day_end, **extra}

    def schedule(pid, room, start, end, kind="class_schedule", source="registrar", **extra):
        return grant(pid, "ROOM", room, start, end, kind, source, **extra)

    def lab_pass(pid, room, start, end):
        return grant(pid, "PASS", room, start, end, "temporary_pass", "invigilator", issued_by="invigilator-01")

    def status(source, value, version):
        return {"source": source, "status": value, "version": version, "updated_at": iso(now)}

    identities = [
        {"person_id": "P001", "name": "Test Student A", "role": "student", "status": "active",
         "rfid_card_id": "CARD-A1", "face_ref": "P001", "source": "registrar", "version": 3, "updated_at": iso(now)},
        {"person_id": "P002", "name": "Test Student B", "role": "student", "status": "suspended",
         "rfid_card_id": "CARD-B2", "face_ref": "P002", "source": "disciplinary_office", "version": 5, "updated_at": iso(now)},
        {"person_id": "P003", "name": "Test Staff C", "role": "staff", "status": "active",
         "rfid_card_id": "CARD-C3", "face_ref": "P003", "source": "hr", "version": 1, "updated_at": iso(now)},
    ]
    grants = [
        {"person_id": "P001", "grant_key": f"ROOM#LAB3#{iso(now - h(1))}",
         "room_id": "LAB3", "valid_from": iso(now - h(1)), "valid_to": iso(now + h(3)),
         "type": "exam_schedule", "source": "exam_office", "version": 2, "expires_at": day_end},
        {"person_id": "P003", "grant_key": f"PASS#LAB1#{iso(now)}",
         "room_id": "LAB1", "valid_from": iso(now), "valid_to": iso(now + m(90)),
         "type": "temporary_pass", "issued_by": "invigilator-01", "source": "invigilator", "version": 1, "expires_at": day_end},
    ]
    revocations = [
        {"subject_id": "CARD-X9", "reason": "card reported lost", "revoked_at": iso(now), "version": 1},
        # Revocation feed health per card issuer (written by the feed sync job in production).
        {"subject_id": "SYNC#campus", "last_refreshed_at": iso(now), "status": "ok"},
    ]

    # Scenarios S1..S5. Room LAB3 unless noted.
    #   S1 active + scheduled -> ALLOW;  S2 weak match -> REQUEST_VERIFICATION, then ALLOW with fingerprint
    #   S3 suspended -> DENY;  S4 card reported lost -> DENY;  S5 exam starts in 2h -> DENY (not scheduled now)
    identities += [person("S1"), person("S2"), person("S3", "suspended", "disciplinary_office"),
                   person("S4"), person("S5")]
    grants += [schedule(p, "LAB3", now - h(1), now + h(3)) for p in ("S1", "S2", "S3", "S4")]
    grants += [schedule("S5", "EXAMHALL", now + h(2), now + h(5), "exam_schedule", "exam_office")]
    revocations += [{"subject_id": "CARD-S4", "reason": "card reported lost", "revoked_at": iso(now), "version": 1}]

    # Judge scenarios J1..J5.
    #   J1 spoof: valid card + face 99, liveness SPOOF                 -> DENY
    #   J2 registrar says active (v4), disciplinary office suspended   -> DENY (higher authority wins)
    #   J3 exam in LAB2 needs schedule AND lab pass, both valid        -> ALLOW
    #      same in LAB4 but the lab pass expired 30 min ago             -> DENY
    #   J4 contractor card; that issuer's revocation feed failed 3h ago -> EXAMHALL DENY, LAB3 REQUEST_VERIFICATION
    #   J5 registrar active v3 vs HR inactive v3 (equal authority)      -> LAB3 REQUEST_VERIFICATION, EXAMHALL DENY
    identities += [
        person("J1"),
        person("J2", status_records=[status("registrar", "active", 4), status("disciplinary_office", "suspended", 2)]),
        person("J3"),
        person("J4", card_issuer="contractor-office", role="contractor"),
        person("J5", status_records=[status("registrar", "active", 3), status("hr", "inactive", 3)]),
    ]
    grants += [
        schedule("J1", "LAB3", now - h(1), now + h(3)),
        schedule("J2", "LAB3", now - h(1), now + h(3)),
        schedule("J3", "LAB2", now - m(30), now + h(2), "exam_schedule", "exam_office", requires_pass=True),
        lab_pass("J3", "LAB2", now - m(30), now + m(90)),
        schedule("J3", "LAB4", now - m(30), now + h(2), "exam_schedule", "exam_office", requires_pass=True),
        lab_pass("J3", "LAB4", now - h(3), now - m(30)),
        schedule("J4", "EXAMHALL", now - m(30), now + h(2), "exam_schedule", "exam_office"),
        schedule("J4", "LAB3", now - h(1), now + h(3)),
        schedule("J5", "LAB3", now - h(1), now + h(3)),
        schedule("J5", "EXAMHALL", now - m(30), now + h(2), "exam_schedule", "exam_office"),
    ]
    revocations += [{"subject_id": "SYNC#contractor-office", "last_refreshed_at": iso(now - h(3)),
                     "status": "refresh_failed", "last_error": "issuer endpoint unreachable"}]
    return {"identities": identities, "authorization": grants, "revocations": revocations}


def main():
    import boto3

    p = argparse.ArgumentParser()
    p.add_argument("--stage", default="dev")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--refresh-sync", action="store_true", help="only refresh the campus revocation feed status")
    a = p.parse_args()
    db = boto3.resource("dynamodb", region_name=a.region)
    now = datetime.now(timezone.utc)
    data = build(now)
    if a.refresh_sync:
        data = {"revocations": [r for r in data["revocations"] if r["subject_id"] == "SYNC#campus"]}
    for table, items in data.items():
        t = db.Table(f"verigate-{a.stage}-{table}")
        for item in items:
            t.put_item(Item=item)
    print("Seeded " + ", ".join(f"{len(v)} {k}" for k, v in data.items()) + " (synthetic).")


if __name__ == "__main__":
    main()
