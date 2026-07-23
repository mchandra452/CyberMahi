from __future__ import annotations

from soclab.cli import execute_analysis


def test_complete_attack_scenario_correlates(root):
    findings, incident, _ = execute_analysis(root, write=False)
    assert {f"DET{number:03d}" for number in range(1, 11)} <= {
        item.detection_id for item in findings
    }
    assert incident.incident_id == "INC-NFS-2025-001"
    assert incident.confidence == "high"
    assert incident.severity == "high"
    assert set(incident.entities) == {
        "Account",
        "Application",
        "ApplicationId",
        "Domain",
        "Host",
        "IP",
        "Mailbox",
        "Process",
        "URL",
    }
    assert "analyst1@northbridge.example" in incident.entities["Account"]
    assert incident.entities["URL"] == ("https://microsoft-auth-check.example/review",)
    assert incident.entities["ApplicationId"] == (
        "00000000-0000-4000-8000-000000000501",
    )
    assert {"winword.exe", "powershell.exe"} <= set(incident.entities["Process"])
    assert len(incident.linked_detections) >= 8
