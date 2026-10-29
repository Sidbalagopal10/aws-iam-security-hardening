"""Identify potentially dangerous IAM privilege-escalation permissions."""

from fnmatch import fnmatchcase


ESCALATION_ACTIONS = {
    "iam:AttachUserPolicy": "Attach policies to IAM users",
    "iam:PutUserPolicy": "Create or replace inline user policies",
    "iam:CreatePolicyVersion": "Create a new managed policy version",
    "iam:SetDefaultPolicyVersion": "Activate an existing managed policy version",
    "iam:PassRole": "Pass an IAM role to an AWS service",
    "sts:AssumeRole": "Assume another IAM role",
}


def audit_privilege_escalation(policy):
    """Flag potential escalation capabilities, including wildcard actions."""
    findings = []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements):
        if statement.get("Effect", "").lower() != "allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        for pattern in actions:
            if not isinstance(pattern, str):
                continue

            for risky_action, description in ESCALATION_ACTIONS.items():
                if not fnmatchcase(
                    risky_action.lower(),
                    pattern.lower()
                ):
                    continue

                findings.append({
                    "severity": "HIGH" if "*" in resources else "MEDIUM",
                    "issue": "Potential IAM privilege escalation",
                    "action": risky_action,
                    "matched_policy_action": pattern,
                    "description": description,
                    "resources": resources,
                    "statement_index": index,
                    "condition_present": bool(statement.get("Condition")),
                    "exploitable": "Not determined"
                })

    return findings
