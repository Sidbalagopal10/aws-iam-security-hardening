from src.security_auditor import audit_iam_policy


def test_unified_report_preserves_condition_context():
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

    report = audit_iam_policy("ConditionalTestPolicy", policy)

    findings = [
        finding for finding in report["findings"]
        if finding["category"] == "IAM_POLICY"
    ]

    assert len(findings) == 1
    assert findings[0]["condition_present"] is True
    assert findings[0]["effective_access_verified"] is False


def test_unified_report_preserves_policy_identity():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }]
    }

    report = audit_iam_policy("FinanceAdminPolicy", policy)

    assert report["findings"]

    for finding in report["findings"]:
        assert finding["policy_name"] == "FinanceAdminPolicy"
        assert finding["matched_policy_action"] == "iam:*"


def test_unified_report_preserves_role_identity():
    from src.security_auditor import audit_iam_trust_policy

    trust_policy = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole"
        }]
    }

    report = audit_iam_trust_policy(
        "FinanceAuditRole",
        trust_policy
    )

    assert len(report["findings"]) == 1
    assert report["findings"][0]["role_name"] == "FinanceAuditRole"
