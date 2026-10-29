"""Offline IAM identity-policy security checks."""

SENSITIVE_ACTIONS = {
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "sts:AssumeRole",
}


def audit_policy(policy):
    """Return security findings for an IAM policy document."""
    findings = []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        for action in actions:
            if not isinstance(action, str):
                continue

            if action.lower() in ("*", "iam:*"):
                severity = "CRITICAL"
                issue = "Broad administrative permissions"

            elif (
                action.lower() in
                {a.lower() for a in SENSITIVE_ACTIONS}
                and "*" in resources
            ):
                severity = "HIGH"
                issue = "Sensitive action on all resources"

            elif "*" in resources:
                severity = "MEDIUM"
                issue = "Wildcard resource permissions"

            else:
                continue

            findings.append({
                "severity": severity,
                "issue": issue,
                "action": action,
                "resources": resources,
                "statement_index": index,
                "condition_present": bool(statement.get("Condition")),
                "effective_access_verified": False,
            })

    return findings
