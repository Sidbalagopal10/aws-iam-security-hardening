from src.trust_policy_auditor import audit_trust_policy


def test_detects_wildcard_principal():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole"
        }]
    }

    findings = audit_trust_policy(policy)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_detects_wildcard_aws_principal():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole"
        }]
    }

    assert len(audit_trust_policy(policy)) == 1


def test_inactive_sentinelcore_role_not_flagged():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyRoleAssumptionUntilConfigured",
            "Effect": "Deny",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:root"
            },
            "Action": "sts:AssumeRole"
        }]
    }

    assert audit_trust_policy(policy) == []


def test_specific_trusted_role_not_flagged():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:role/TrustedRole"
            },
            "Action": "sts:AssumeRole"
        }]
    }

    assert audit_trust_policy(policy) == []
