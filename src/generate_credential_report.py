"""Generate an offline IAM credential security report."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from src.credential_auditor import audit_credentials


def main():
    source = Path("sample_data/iam_credential_report.csv")
    destination = Path("reports/iam_credential_security_report.json")

    with source.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    findings = audit_credentials(
        rows,
        now=datetime.now(timezone.utc),
        stale_days=90
    )

    report = {
        "project": "SentinelCore IAM Security Audit",
        "mode": "OFFLINE",
        "assessment": "IAM Credential Security",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "users_scanned": len(rows),
        "total_findings": len(findings),
        "findings": findings
    }

    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("IAM credential security audit completed.")
    print(f"Users scanned: {report['users_scanned']}")
    print(f"Total findings: {report['total_findings']}")

    for finding in findings:
        print(
            f"{finding['severity']} | "
            f"{finding['user']} | "
            f"{finding['issue']}"
        )

    print(f"Report saved: {destination}")


if __name__ == "__main__":
    main()
