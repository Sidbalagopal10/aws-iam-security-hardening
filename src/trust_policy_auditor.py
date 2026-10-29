"""Offline security checks for AWS IAM role trust policies."""


def audit_trust_policy(policy):
    """Flag potentially broad role-assumption trust relationships."""
    findings = []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        actions = [a.lower() for a in actions if isinstance(a, str)]

        if not any(
            a in ("sts:assumerole", "sts:*", "*")
            for a in actions
        ):
            continue

        principal = statement.get("Principal")
        if principal is None:
            continue

        wildcard = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and (
                    principal.get("AWS") == "*"
                    or (
                        isinstance(principal.get("AWS"), list)
                        and "*" in principal["AWS"]
                    )
                )
            )
        )

        if wildcard:
            findings.append({
                "severity": "HIGH",
                "issue": "Broad role trust principal",
                "statement_index": index,
                "principal": principal,
                "description": (
                    "An Allow statement permits a wildcard principal "
                    "to request role assumption. Review conditions, "
                    "other policy controls, and effective access."
                ),
                "exploitable": "Not determined"
            })

    return findings
