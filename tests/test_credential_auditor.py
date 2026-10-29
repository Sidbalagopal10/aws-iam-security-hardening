from datetime import datetime, timezone

from src.credential_auditor import audit_credentials


NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)


def test_detects_missing_mfa():
    rows = [{
        "user": "developer-test",
        "password_enabled": "true",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_2_active": "false"
    }]

    findings = audit_credentials(rows, now=NOW)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_detects_old_active_key():
    rows = [{
        "user": "automation-test",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": "2026-01-01T00:00:00+00:00",
        "access_key_2_active": "false"
    }]

    findings = audit_credentials(rows, now=NOW)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["access_key_slot"] == 1


def test_no_findings_for_mfa_protected_user():
    rows = [{
        "user": "secure-test",
        "password_enabled": "true",
        "mfa_active": "true",
        "access_key_1_active": "false",
        "access_key_2_active": "false"
    }]

    assert audit_credentials(rows, now=NOW) == []


def test_root_account_is_skipped():
    rows = [{
        "user": "<root_account>",
        "password_enabled": "true",
        "mfa_active": "false"
    }]

    assert audit_credentials(rows, now=NOW) == []


def test_future_access_key_date_is_not_stale():
    from datetime import datetime, timezone

    rows = [{
        "user": "future-test",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": "2030-01-01T00:00:00Z"
    }]

    findings = audit_credentials(
        rows,
        now=datetime(2026, 10, 28, tzinfo=timezone.utc)
    )

    assert findings == []


def test_naive_now_does_not_crash():
    from datetime import datetime

    rows = [{
        "user": "legacy-test",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": "2025-01-01T00:00:00Z"
    }]

    findings = audit_credentials(
        rows,
        now=datetime(2026, 10, 28)
    )

    assert len(findings) == 1
    assert findings[0]["user"] == "legacy-test"


def test_two_stale_access_keys_remain_distinct():
    from datetime import datetime, timezone

    rows = [{
        "user": "automation-test",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": "2025-01-01T00:00:00Z",
        "access_key_2_active": "true",
        "access_key_2_last_rotated": "2025-02-01T00:00:00Z"
    }]

    findings = audit_credentials(
        rows,
        now=datetime(2026, 10, 28, tzinfo=timezone.utc)
    )

    assert len(findings) == 2
    assert {f["access_key_slot"] for f in findings} == {1, 2}
