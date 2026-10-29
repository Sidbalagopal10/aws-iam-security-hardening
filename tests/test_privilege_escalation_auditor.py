from src.privilege_escalation_auditor import audit_privilege_escalation


def test_detects_policy_attachment_risk():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:AttachUserPolicy",
            "Resource": "*"
        }]
    }

    findings = audit_privilege_escalation(policy)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_detects_role_passing_risk():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*"
        }]
    }

    findings = audit_privilege_escalation(policy)

    assert findings[0]["action"] == "iam:PassRole"


def test_scoped_assume_role_is_flagged_for_review():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/TestRole"
        }]
    }

    findings = audit_privilege_escalation(policy)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_explicit_deny_is_not_flagged():
    policy = {
        "Statement": [{
            "Effect": "Deny",
            "Action": "iam:AttachUserPolicy",
            "Resource": "*"
        }]
    }

    assert audit_privilege_escalation(policy) == []


def test_detects_wildcard_policy_attachment():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:Attach*",
            "Resource": "*"
        }]
    }

    findings = audit_privilege_escalation(policy)

    assert any(
        f["action"] == "iam:AttachUserPolicy"
        for f in findings
    )


def test_detects_iam_service_wildcard():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }]
    }

    findings = audit_privilege_escalation(policy)

    assert any(
        f["action"] == "iam:CreatePolicyVersion"
        for f in findings
    )


def test_does_not_match_unrelated_actions():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }]
    }

    assert audit_privilege_escalation(policy) == []
