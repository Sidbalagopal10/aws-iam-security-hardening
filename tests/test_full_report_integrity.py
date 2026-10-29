"""Integration tests for SentinelCore consolidated reporting."""

import json

from src.generate_full_report import main


def test_full_report_preserves_all_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # Sample data is referenced relative to the project root.
    # Copy the required fixtures into the temporary test directory.
    from pathlib import Path
    import shutil

    project_root = Path(__file__).resolve().parents[1]
    shutil.copytree(
        project_root / "sample_data",
        tmp_path / "sample_data"
    )

    main()

    report_path = tmp_path / "reports/sentinelcore_full_report.json"
    report = json.loads(report_path.read_text())

    findings = report["findings"]
    groups = report["grouped_risks"]
    summary = report["summary"]

    assert summary["total_findings"] == len(findings)
    assert summary["total_grouped_risks"] == len(groups)

    assert sum(
        len(group["findings"]) for group in groups
    ) == len(findings)

    assert sum(
        summary["severity_counts"].values()
    ) == len(findings)

    assert sum(
        summary["grouped_severity_counts"].values()
    ) == len(groups)


def test_full_report_sample_counts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    from pathlib import Path
    import shutil

    project_root = Path(__file__).resolve().parents[1]
    shutil.copytree(
        project_root / "sample_data",
        tmp_path / "sample_data"
    )

    main()

    report = json.loads(
        (tmp_path / "reports/sentinelcore_full_report.json").read_text()
    )

    assert report["mode"] == "OFFLINE"
    assert report["summary"]["total_findings"] == 10
    assert report["summary"]["total_grouped_risks"] == 5

    assert report["summary"]["grouped_severity_counts"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 2,
        "LOW": 0
    }
