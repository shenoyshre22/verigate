from datetime import timedelta

from .conftest import NOW, iso


def test_identity_by_person_with_active_schedule(loader):
    lc = loader.load(room_id="lab3", person_id="P001", now=NOW)
    assert lc.person_id == "P001" and lc.context.schedule_ok and not lc.context.temp_pass_valid
    assert lc.context.records_fresh and not lc.context.revoked and not lc.context.room_sensitive


def test_identity_by_card_via_gsi(loader):
    lc = loader.load(room_id="LAB3", rfid_card_id="CARD-A1", now=NOW)
    assert lc.person_id == "P001" and lc.card_person_id == "P001"


def test_unknown_card_gives_no_identity_even_with_person_id(loader):
    lc = loader.load(room_id="LAB3", person_id="P001", rfid_card_id="CARD-NOPE", now=NOW)
    assert lc.context.person is None


def test_duplicated_card_gives_no_identity(loader, tables):
    tables["identities"].put_item(Item={"person_id": "P009", "status": "active", "rfid_card_id": "CARD-A1",
                                        "updated_at": iso(NOW)})
    assert loader.load(room_id="LAB3", rfid_card_id="CARD-A1", now=NOW).context.person is None


def test_expired_grant_is_not_scheduled(loader):
    assert not loader.load(room_id="LAB9", person_id="P001", now=NOW).context.schedule_ok


def test_grant_for_other_room_does_not_count(loader):
    assert not loader.load(room_id="LAB1", person_id="P001", now=NOW).context.schedule_ok


def test_temporary_pass_valid_inside_window_only(loader):
    assert loader.load(room_id="LAB1", person_id="P003", now=NOW).context.temp_pass_valid
    assert not loader.load(room_id="LAB1", person_id="P003", now=NOW + timedelta(hours=2)).context.temp_pass_valid


def test_revocation_by_card_and_by_person(loader, tables):
    tables["identities"].put_item(Item={"person_id": "P010", "status": "active", "rfid_card_id": "CARD-X9",
                                        "updated_at": iso(NOW)})
    assert loader.load(room_id="LAB3", rfid_card_id="CARD-X9", now=NOW).context.revoked
    tables["revocations"].put_item(Item={"subject_id": "P003", "revoked_at": iso(NOW)})
    assert loader.load(room_id="LAB1", person_id="P003", now=NOW).context.revoked


def test_old_or_missing_updated_at_is_stale(loader, tables, monkeypatch):
    monkeypatch.setenv("FRESHNESS_MINUTES", "30")
    assert not loader.load(room_id="LAB3", person_id="P001", now=NOW).context.records_fresh  # 60 min old
    tables["identities"].put_item(Item={"person_id": "P004", "status": "active"})
    assert not loader.load(room_id="LAB3", person_id="P004", now=NOW).context.records_fresh


def test_future_updated_at_is_stale(loader, tables):
    tables["identities"].put_item(Item={"person_id": "P005", "status": "active",
                                        "updated_at": iso(NOW + timedelta(days=1))})
    assert not loader.load(room_id="LAB3", person_id="P005", now=NOW).context.records_fresh


def test_sensitive_rooms_from_env(loader, monkeypatch):
    assert loader.load(room_id="examhall", person_id="P001", now=NOW).context.room_sensitive
    monkeypatch.setenv("SENSITIVE_ROOMS", "LAB3")
    assert loader.load(room_id="LAB3", person_id="P001", now=NOW).context.room_sensitive
