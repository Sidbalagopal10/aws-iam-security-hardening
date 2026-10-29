"""Unified offline AWS IAM security auditing engine."""

from datetime import datetime, timezone
from src.iam_policy_auditor import audit_policy
from src.privilege_escalation_auditor import audit_privilege_escalation


REMEDIATIONS = {
    "Broad administrative permissions":
        "Replace broad administrative actions with narrowly scoped permissions.",
    "Sensitive action on all resources":
        "Restrict sensitive IAM actions to approved resources where supported.",
    "Wildcard resource permissions":
        "Review whether wildcard resources are necessary and restrict scope where possible.",
    "Potential IAM privilege escalation":
        "Review the action, target resources, trust relationships, and effective permissions."
}


def audit_iam_policy(policy_name, policy_document):
    """Audit one policy and return a structured report."""
    findings = []

    checks = [
        ("IAM_POLICY", audit_policy),
        ("PRIVILEGE_ESCALATION", audit_privilege_escalation)
    ]

    for category, detector in checks:
        for finding in detector(policy_document):
            findings.append({
                "category": category,
                "policy_name": policy_name,
                "severity": finding["severity"],
                "issue": finding["issue"],
                "action": finding["action"],
                "matched_policy_action": finding.get(
                    "matched_policy_action", finding["action"]
                ),
                "resources": finding["resources"],
                "statement_index": finding["statement_index"],
                "condition_present": finding.get("condition_present"),
                "effective_access_verified": False,
                "remediation": REMEDIATIONS.get(
                    finding["issue"],
                    "Review the affected IAM policy."
                )
            })

    counts = {
        level: sum(
            f["severity"] == level for f in findings
        )
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    return {
        "project": "SentinelCore IAM Security Audit",
        "mode": "OFFLINE",
        "policy_name": policy_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts
        },
        "findings": findings
    }


def audit_iam_trust_policy(role_name, trust_policy):
    """Audit an IAM role trust policy and return structured findings."""
    from src.trust_policy_auditor import audit_trust_policy

    findings = []

    for finding in audit_trust_policy(trust_policy):
        findings.append({
            "category": "TRUST_POLICY",
            "role_name": role_name,
            "severity": finding["severity"],
            "issue": finding["issue"],
            "statement_index": finding["statement_index"],
            "principal": finding["principal"],
            "remediation": (
                "Restrict trusted principals to approved identities "
                "and review role-assumption conditions."
            )
        })

    return {
        "role_name": role_name,
        "total_findings": len(findings),
        "findings": findings
    }
