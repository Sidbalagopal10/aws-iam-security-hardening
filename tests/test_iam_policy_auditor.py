from src.iam_policy_auditor import audit_policy


def test_detects_broad_iam_permissions():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }]
    }

    findings = audit_policy(policy)

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_detects_sensitive_wildcard_permissions():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:AttachUserPolicy",
            "Resource": "*"
        }]
    }

    findings = audit_policy(policy)

    assert findings[0]["severity"] == "HIGH"


def test_ignores_explicit_deny():
    policy = {
        "Statement": [{
            "Effect": "Deny",
            "Action": "iam:*",
            "Resource": "*"
        }]
    }

    assert audit_policy(policy) == []


def test_scoped_permissions():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example-bucket/*"
        }]
    }

    assert audit_policy(policy) == []


def test_wildcard_resource_finding_records_conditions():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/Department": "Finance"
                }
            }
        }]
    }

    findings = audit_policy(policy)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["condition_present"] is True
    assert findings[0]["effective_access_verified"] is False
