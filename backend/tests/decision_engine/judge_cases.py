"""The judges' five scenarios: one definition used by the tests and by the live run on the deployed API.

Each case: (id, title, request body for POST /decision/evaluate, expected decision, reason fragment).
"""
GOOD = {"liveness": 97.0, "face_similarity": 99.0}


def ev(pid, **kw):
    return {**GOOD, "face_person_id": pid, **kw}


JUDGE_CASES = [
    ("J1", "Spoof: face 99 + valid RFID, liveness SPOOF",
     {"person_id": "J1", "rfid_card_id": "CARD-J1", "room_id": "LAB3",
      "evidence": {"face_person_id": "J1", "face_similarity": 99.0, "liveness_status": "SPOOF"}},
     "DENY", "spoof suspected"),
    ("J2", "Suspended: all biometrics pass, disciplinary office says suspended",
     {"person_id": "J2", "rfid_card_id": "CARD-J2", "room_id": "LAB3",
      "evidence": ev("J2", challenge_passed=True)},
     "DENY", "suspended"),
    ("J3", "Temporary exam pass: exam schedule + lab pass both valid now",
     {"person_id": "J3", "room_id": "LAB2", "evidence": ev("J3")},
     "ALLOW", "authorized for this room now"),
    ("J3-expired", "Temporary exam pass: exam schedule valid, lab pass expired",
     {"person_id": "J3", "room_id": "LAB4", "evidence": ev("J3")},
     "DENY", "requires a valid temporary lab pass"),
    ("J4", "Stale revocation feed, sensitive room (EXAMHALL)",
     {"person_id": "J4", "rfid_card_id": "CARD-J4", "room_id": "EXAMHALL", "evidence": ev("J4")},
     "DENY", "revocation list could not be refreshed"),
    ("J4-normal", "Stale revocation feed, normal room (LAB3)",
     {"person_id": "J4", "rfid_card_id": "CARD-J4", "room_id": "LAB3", "evidence": ev("J4")},
     "REQUEST_VERIFICATION", "revocation list could not be refreshed"),
    ("J5", "Conflicting equally authoritative records (registrar vs HR)",
     {"person_id": "J5", "room_id": "LAB3", "evidence": ev("J5")},
     "REQUEST_VERIFICATION", "conflicting records"),
    ("J5-sensitive", "Conflicting records, sensitive room (EXAMHALL)",
     {"person_id": "J5", "room_id": "EXAMHALL", "evidence": ev("J5")},
     "DENY", "conflicting authoritative records for a sensitive room"),
]
