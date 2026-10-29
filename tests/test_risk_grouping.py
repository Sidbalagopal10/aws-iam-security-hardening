from src.risk_grouping import group_findings


def test_groups_wildcard_expansion_findings():
    findings = [
        {
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "statement_index": 0,
            "action": "iam:AttachUserPolicy",
            "matched_policy_action": "iam:*"
        },
        {
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "statement_index": 0,
            "action": "iam:PassRole",
            "matched_policy_action": "iam:*"
        }
    ]

    groups = group_findings(findings)

    assert len(groups) == 1
    assert len(groups[0]["findings"]) == 2


def test_preserves_highest_severity():
    findings = [
        {
            "category": "IAM_POLICY",
            "severity": "CRITICAL",
            "statement_index": 0,
            "action": "iam:*"
        },
        {
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "statement_index": 0,
            "action": "iam:PassRole",
            "matched_policy_action": "iam:*"
        }
    ]

    groups = group_findings(findings)

    assert len(groups) == 1
    assert groups[0]["severity"] == "CRITICAL"


def test_keeps_different_users_separate():
    findings = [
        {
            "category": "CREDENTIAL_SECURITY",
            "severity": "HIGH",
            "user": "developer-one",
            "issue": "Missing MFA"
        },
        {
            "category": "CREDENTIAL_SECURITY",
            "severity": "HIGH",
            "user": "developer-two",
            "issue": "Missing MFA"
        }
    ]

    assert len(group_findings(findings)) == 2


def test_groups_multiple_actions_in_same_policy_statement():
    findings = [
        {
            "category": "IAM_POLICY",
            "policy_name": "AdminPolicy",
            "severity": "CRITICAL",
            "statement_index": 0,
            "action": "iam:*"
        },
        {
            "category": "PRIVILEGE_ESCALATION",
            "policy_name": "AdminPolicy",
            "severity": "HIGH",
            "statement_index": 0,
            "action": "iam:PassRole",
            "matched_policy_action": "iam:*"
        },
        {
            "category": "PRIVILEGE_ESCALATION",
            "policy_name": "AdminPolicy",
            "severity": "HIGH",
            "statement_index": 0,
            "action": "iam:AttachUserPolicy",
            "matched_policy_action": "iam:Attach*"
        }
    ]

    groups = group_findings(findings)

    assert len(groups) == 2
    assert sorted(
        len(group["findings"]) for group in groups
    ) == [1, 2]
    assert sorted(
        group["severity"] for group in groups
    ) == ["CRITICAL", "HIGH"]


def test_keeps_distinct_policy_actions_separate():
    findings = [
        {
            "category": "IAM_POLICY",
            "policy_name": "SamplePolicy",
            "severity": "CRITICAL",
            "statement_index": 0,
            "action": "iam:*"
        },
        {
            "category": "PRIVILEGE_ESCALATION",
            "policy_name": "SamplePolicy",
            "severity": "HIGH",
            "statement_index": 0,
            "action": "iam:PassRole",
            "matched_policy_action": "iam:*"
        },
        {
            "category": "IAM_POLICY",
            "policy_name": "SamplePolicy",
            "severity": "MEDIUM",
            "statement_index": 0,
            "action": "s3:GetObject"
        }
    ]

    groups = group_findings(findings)

    assert len(groups) == 2
    assert sorted(len(group["findings"]) for group in groups) == [1, 2]


def test_keeps_different_iam_policies_separate():
    findings = [
        {
            "category": "IAM_POLICY",
            "policy_name": "FinanceAdminPolicy",
            "severity": "CRITICAL",
            "statement_index": 0,
            "action": "iam:*"
        },
        {
            "category": "IAM_POLICY",
            "policy_name": "DeveloperAdminPolicy",
            "severity": "CRITICAL",
            "statement_index": 0,
            "action": "iam:*"
        }
    ]

    groups = group_findings(findings)

    assert len(groups) == 2
    assert all(len(group["findings"]) == 1 for group in groups)


def test_keeps_different_roles_separate():
    findings = [
        {
            "category": "TRUST_POLICY",
            "role_name": "FinanceAuditRole",
            "severity": "HIGH",
            "statement_index": 0,
            "issue": "Broad role trust principal"
        },
        {
            "category": "TRUST_POLICY",
            "role_name": "DeveloperAuditRole",
            "severity": "HIGH",
            "statement_index": 0,
            "issue": "Broad role trust principal"
        }
    ]

    assert len(group_findings(findings)) == 2


def test_keeps_multiple_issues_for_same_user_separate():
    findings = [
        {
            "category": "CREDENTIAL_SECURITY",
            "user": "developer-test",
            "severity": "HIGH",
            "issue": "Console password enabled without MFA"
        },
        {
            "category": "CREDENTIAL_SECURITY",
            "user": "developer-test",
            "severity": "MEDIUM",
            "issue": "Active access key exceeds rotation threshold"
        }
    ]

    assert len(group_findings(findings)) == 2
