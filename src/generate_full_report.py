"""Generate a consolidated offline SentinelCore IAM report."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from src.security_auditor import (
    audit_iam_policy,
    audit_iam_trust_policy,
)
from src.credential_auditor import audit_credentials
from src.risk_grouping import group_findings


def load_json(path):
    with Path(path).open(encoding="utf-8") as file:
        return json.load(file)


def main():
    policy = load_json("sample_data/vulnerable_policy.json")
    trust_policy = load_json(
        "sample_data/vulnerable_trust_policy.json"
    )

    with Path(
        "sample_data/iam_credential_report.csv"
    ).open(newline="", encoding="utf-8") as file:
        credential_rows = list(csv.DictReader(file))

    policy_report = audit_iam_policy(
        "SentinelCore-Sample-Vulnerable-Policy",
        policy
    )

    trust_report = audit_iam_trust_policy(
        "SentinelCore-Sample-Vulnerable-Role",
        trust_policy
    )

    credential_findings = audit_credentials(credential_rows)

    findings = (
        policy_report["findings"]
        + trust_report["findings"]
        + credential_findings
    )

    counts = {
        severity: sum(
            finding["severity"] == severity
            for finding in findings
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    grouped_risks = group_findings(findings)

    grouped_counts = {
        severity: sum(
            group["severity"] == severity
            for group in grouped_risks
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    report = {
        "project": "SentinelCore",
        "assessment": "AWS IAM Security Assessment",
        "mode": "OFFLINE",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assets_scanned": {
            "iam_policies": 1,
            "role_trust_policies": 1,
            "iam_users": len(credential_rows)
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "total_grouped_risks": len(grouped_risks),
            "grouped_severity_counts": grouped_counts
        },
        "findings": findings,
        "grouped_risks": grouped_risks,
        "limitations": [
            "All findings originate from simulated sample data.",
            "Policy findings are heuristic, not effective-permission analysis.",
            "Overlapping findings may describe the same underlying risk.",
            "Trust conditions and organization-level controls are not fully evaluated."
        ]
    }

    destination = Path("reports/sentinelcore_full_report.json")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("SentinelCore consolidated security audit completed.")
    print("Mode:", report["mode"])
    print("Assets scanned:", report["assets_scanned"])
    print("Total findings:", report["summary"]["total_findings"])
    print("Severity counts:", counts)
    print("Grouped risks:", len(grouped_risks))
    print("Grouped severity counts:", grouped_counts)
    print("Report saved:", destination)


if __name__ == "__main__":
    main()
