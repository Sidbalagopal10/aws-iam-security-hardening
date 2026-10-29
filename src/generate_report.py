"""Generate an offline IAM security assessment report."""

import json
from pathlib import Path
from src.security_auditor import audit_iam_policy


def main():
    source = Path("sample_data/vulnerable_policy.json")
    destination = Path("reports/iam_security_report.json")

    with source.open(encoding="utf-8") as file:
        policy = json.load(file)

    report = audit_iam_policy(
        "SentinelCore-Sample-Vulnerable-Policy",
        policy
    )

    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("IAM security audit completed.")
    print(f"Total findings: {report['summary']['total_findings']}")
    print(f"Report saved: {destination}")


if __name__ == "__main__":
    main()
