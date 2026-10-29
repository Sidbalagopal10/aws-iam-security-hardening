"""Offline IAM credential-report security checks."""

from datetime import datetime, timezone


def audit_credentials(rows, now=None, stale_days=90):
    """Audit parsed AWS IAM credential report rows."""
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None or now.utcoffset() is None:
        # Interpret naive caller-provided timestamps as UTC.
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    findings = []

    for row in rows:
        username = row.get("user", "UNKNOWN")

        # AWS credential reports represent the account root separately.
        # Handle root-specific controls in a dedicated future check.
        if username == "<root_account>":
            continue

        password_enabled = row.get("password_enabled", "").lower()
        mfa_active = row.get("mfa_active", "").lower()

        if password_enabled == "true" and mfa_active == "false":
            findings.append({
                "severity": "HIGH",
                "category": "CREDENTIAL_SECURITY",
                "user": username,
                "issue": "Console password enabled without MFA",
                "remediation": "Enable MFA for this IAM user."
            })

        for key_number in (1, 2):
            active = row.get(
                f"access_key_{key_number}_active", ""
            ).lower()

            created = row.get(
                f"access_key_{key_number}_last_rotated", ""
            )

            if active != "true" or not created or created == "N/A":
                continue

            try:
                created_at = datetime.fromisoformat(
                    created.replace("Z", "+00:00")
                )
                if created_at.tzinfo is None:
                    continue
            except ValueError:
                continue

            age_days = (now - created_at).days

            if age_days > stale_days:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "CREDENTIAL_SECURITY",
                    "user": username,
                    "issue": "Active access key exceeds rotation threshold",
                    "access_key_slot": key_number,
                    "age_days": age_days,
                    "remediation": (
                        "Review key usage and replace long-lived "
                        "credentials with temporary credentials where possible."
                    )
                })

    return findings
