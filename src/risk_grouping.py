"""Group related SentinelCore security findings."""

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


def group_findings(findings):
    """Group related findings while retaining their original details."""
    groups = {}

    for finding in findings:
        category = finding["category"]

        if category in ("IAM_POLICY", "PRIVILEGE_ESCALATION"):
            key = (
                "POLICY_ACTION",
                finding.get("policy_name", "default"),
                finding.get("statement_index"),
                finding.get("matched_policy_action")
                or finding.get("action")
            )

        elif category == "TRUST_POLICY":
            key = (
                "TRUST_POLICY",
                finding.get("role_name", "default"),
                finding.get("statement_index")
            )

        elif category == "CREDENTIAL_SECURITY":
            key = (
                "CREDENTIAL_SECURITY",
                finding.get("user"),
                finding.get("issue"),
                finding.get("access_key_slot")
            )

        else:
            key = (
                category,
                finding.get("issue"),
                finding.get("action")
            )

        if key not in groups:
            groups[key] = {
                "severity": finding["severity"],
                "categories": [],
                "findings": []
            }

        group = groups[key]
        group["findings"].append(finding)

        if category not in group["categories"]:
            group["categories"].append(category)

        if (
            SEVERITY_ORDER[finding["severity"]]
            > SEVERITY_ORDER[group["severity"]]
        ):
            group["severity"] = finding["severity"]

    return list(groups.values())
