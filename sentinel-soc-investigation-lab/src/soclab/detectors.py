"""Offline Python equivalents of DET001-DET009.

These functions regression-test detection intent against synthetic records. They do
not parse or execute KQL and are not a substitute for validating rules in Sentinel.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import timedelta

from soclab.models import Event, Finding

Detector = Callable[[list[Event], dict], list[Finding]]

NAMES = {
    "DET001": "Password Spray Across Cloud Accounts",
    "DET002": "Successful Authentication After Failure Burst",
    "DET003": "Unusual Authentication Context",
    "DET004": "Phishing-Link Indicators",
    "DET005": "Suspicious OAuth Consent",
    "DET006": "External Mail Forwarding Rule",
    "DET007": "Cloud Download Anomaly",
    "DET008": "Office Application Spawning PowerShell",
    "DET009": "New or Rare Domain DNS Activity",
}

ENTITY_TYPES = {
    "DET001": frozenset({"Account", "IP"}),
    "DET002": frozenset({"Account", "IP"}),
    "DET003": frozenset({"Account", "IP", "Host"}),
    "DET004": frozenset({"Account", "Domain", "URL"}),
    "DET005": frozenset({"Account", "Application", "ApplicationId", "IP"}),
    "DET006": frozenset({"Account", "IP", "Mailbox"}),
    "DET007": frozenset({"Account", "IP"}),
    "DET008": frozenset({"Account", "Host", "Process"}),
    "DET009": frozenset({"Account", "Domain", "Host"}),
}


def _finding(
    detection_id: str,
    index: int,
    events: Iterable[Event],
    severity: str,
    confidence: str,
    category: str,
    evidence: str,
) -> Finding:
    selected = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    requested = ENTITY_TYPES[detection_id]
    entity_fields: dict[str, list[str]] = {}
    common_fields = {
        "Account": {event.user for event in selected if event.user},
        "IP": {event.ip_address for event in selected if event.ip_address},
        "Host": {event.device_id for event in selected if event.device_id},
        "Application": {event.application for event in selected if event.application},
    }
    for entity_type, values in common_fields.items():
        if entity_type in requested and values:
            entity_fields[entity_type] = sorted(values)
    for event in selected:
        domain = str(event.attributes.get("Domain") or event.attributes.get("UrlDomain") or "")
        if "Domain" in requested and domain:
            entity_fields.setdefault("Domain", []).append(domain)
        mailbox = str(event.attributes.get("Mailbox", ""))
        if "Mailbox" in requested and mailbox:
            entity_fields.setdefault("Mailbox", []).append(mailbox)
        url = str(event.attributes.get("Url", ""))
        if "URL" in requested and url:
            entity_fields.setdefault("URL", []).append(url)
        app_id = str(event.attributes.get("AppId", ""))
        if "ApplicationId" in requested and app_id:
            entity_fields.setdefault("ApplicationId", []).append(app_id)
        if "Process" in requested:
            for process_field in ("ParentProcess", "ProcessName"):
                process = str(event.attributes.get(process_field, ""))
                if process:
                    entity_fields.setdefault("Process", []).append(process)
    entities = {key: tuple(sorted(set(values))) for key, values in entity_fields.items() if values}
    return Finding(
        finding_id=f"F-{detection_id}-{index:04d}",
        detection_id=detection_id,
        name=NAMES[detection_id],
        timestamp=selected[-1].timestamp,
        severity=severity,
        confidence=confidence,
        category=category,
        event_ids=tuple(event.event_id for event in selected),
        entities=entities,
        evidence=evidence,
    )


def detect_password_spray(events: list[Event], context: dict) -> list[Finding]:
    failures = [
        event
        for event in events
        if event.source_type == "authentication"
        and event.result == "Failure"
        and event.ip_address not in context["known_benign"].get("corporate_egress_ips", [])
        and event.user not in context["known_benign"].get("service_accounts", [])
    ]
    findings: list[Finding] = []
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in failures:
        by_ip[event.ip_address].append(event)
    for source_ip, group in sorted(by_ip.items()):
        group = sorted(group, key=lambda item: item.timestamp)
        for start in group:
            window = [
                item
                for item in group
                if start.timestamp <= item.timestamp <= start.timestamp + timedelta(minutes=10)
            ]
            if len(window) >= 5 and len({item.user for item in window}) >= 4:
                user_count = len({item.user for item in window})
                findings.append(
                    _finding(
                        "DET001",
                        len(findings) + 1,
                        window,
                        "medium",
                        "high",
                        "authentication",
                        f"{len(window)} failures against {user_count} accounts from {source_ip}",
                    )
                )
                break
    return findings


def detect_success_after_failures(events: list[Event], context: dict) -> list[Finding]:
    del context
    auth = [event for event in events if event.source_type == "authentication"]
    findings: list[Finding] = []
    for success in [event for event in auth if event.result == "Success"]:
        failures = [
            event
            for event in auth
            if event.result == "Failure"
            and event.user == success.user
            and timedelta(0) <= success.timestamp - event.timestamp <= timedelta(minutes=15)
        ]
        if len(failures) >= 3:
            findings.append(
                _finding(
                    "DET002",
                    len(findings) + 1,
                    [*failures, success],
                    "high",
                    "high",
                    "authentication",
                    f"Successful sign-in followed {len(failures)} failures for {success.user}",
                )
            )
    return findings


def detect_unusual_authentication(events: list[Event], context: dict) -> list[Finding]:
    findings: list[Finding] = []
    baselines = context["baselines"]
    vpn_ips = set(context["known_benign"].get("vpn_ips", []))
    for event in events:
        if (
            event.source_type != "authentication"
            or event.result != "Success"
            or event.ip_address in vpn_ips
        ):
            continue
        baseline = baselines.get(event.user, {})
        new_country = event.location not in baseline.get("countries", [])
        new_device = bool(event.device_id) and event.device_id not in baseline.get("devices", [])
        risky = event.risk_level.lower() in {"medium", "high"}
        if (new_country or new_device) and risky:
            reasons = ", ".join(
                label
                for label, matched in (
                    ("new country", new_country),
                    ("new device", new_device),
                    ("elevated risk", risky),
                )
                if matched
            )
            findings.append(
                _finding(
                    "DET003",
                    len(findings) + 1,
                    [event],
                    "medium",
                    "medium",
                    "authentication",
                    f"Authentication context differs from baseline: {reasons}",
                )
            )
    return findings


def detect_phishing(events: list[Event], context: dict) -> list[Finding]:
    suspicious_domains = set(context["safe_indicators"].get("suspicious_domains", []))
    findings: list[Finding] = []
    for event in events:
        sender_domain = str(event.attributes.get("SenderDomain", ""))
        url_domain = str(event.attributes.get("UrlDomain", ""))
        mismatch = bool(event.attributes.get("DisplayNameMismatch", False))
        if (
            event.source_type == "email"
            and event.result == "Delivered"
            and mismatch
            and (sender_domain in suspicious_domains or url_domain in suspicious_domains)
        ):
            findings.append(
                _finding(
                    "DET004",
                    len(findings) + 1,
                    [event],
                    "medium",
                    "high",
                    "email",
                    "Delivered message has display-name mismatch and safe suspicious "
                    f"URL domain {url_domain}",
                )
            )
    return findings


def detect_oauth_consent(events: list[Event], context: dict) -> list[Finding]:
    approved_admins = set(context["known_benign"].get("approved_consent_admins", []))
    approved_apps = set(context["known_benign"].get("approved_applications", []))
    high_impact = {"Mail.ReadWrite", "Files.ReadWrite.All", "offline_access"}
    findings: list[Finding] = []
    for event in events:
        scopes = set(event.attributes.get("Scopes", []))
        first_seen = bool(event.attributes.get("FirstSeenApplication", False))
        if (
            event.source_type == "cloud-app"
            and event.action == "ConsentGranted"
            and scopes & high_impact
            and first_seen
            and event.user not in approved_admins
            and event.application not in approved_apps
        ):
            findings.append(
                _finding(
                    "DET005",
                    len(findings) + 1,
                    [event],
                    "high",
                    "medium",
                    "cloud_application",
                    "First-seen application received high-impact scopes: "
                    f"{', '.join(sorted(scopes & high_impact))}",
                )
            )
    return findings


def detect_forwarding(events: list[Event], context: dict) -> list[Finding]:
    approved_domains = set(context["known_benign"].get("approved_forwarding_domains", []))
    findings: list[Finding] = []
    for event in events:
        target_domain = str(event.attributes.get("ForwardingDomain", ""))
        external = bool(event.attributes.get("External", False))
        if (
            event.source_type == "cloud-app"
            and event.action in {"MailboxRuleCreated", "MailboxRuleModified"}
            and external
            and target_domain not in approved_domains
        ):
            findings.append(
                _finding(
                    "DET006",
                    len(findings) + 1,
                    [event],
                    "high",
                    "high",
                    "mailbox",
                    f"Mailbox forwarding was configured to external domain {target_domain}",
                )
            )
    return findings


def detect_download_anomaly(events: list[Event], context: dict) -> list[Finding]:
    backups = set(context["known_benign"].get("backup_accounts", []))
    baselines = context["baselines"]
    findings: list[Finding] = []
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if (
            event.source_type == "cloud-app"
            and event.action == "FileDownloaded"
            and event.user not in backups
        ):
            grouped[(event.scenario_id, event.user)].append(event)
    for (_, user), group in sorted(grouped.items()):
        normal = int(baselines.get(user, {}).get("daily_download_count", 2))
        if len(group) >= max(8, normal * 3):
            findings.append(
                _finding(
                    "DET007",
                    len(findings) + 1,
                    group,
                    "medium",
                    "medium",
                    "cloud_storage",
                    f"{len(group)} downloads exceed static daily baseline of {normal} for {user}",
                )
            )
    return findings


def detect_office_powershell(events: list[Event], context: dict) -> list[Finding]:
    del context
    office = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
    findings: list[Finding] = []
    for event in events:
        parent = str(event.attributes.get("ParentProcess", "")).lower()
        child = str(event.attributes.get("ProcessName", "")).lower()
        if (
            event.source_type == "endpoint-process"
            and parent in office
            and child in {"powershell.exe", "pwsh.exe"}
        ):
            findings.append(
                _finding(
                    "DET008",
                    len(findings) + 1,
                    [event],
                    "high",
                    "high",
                    "endpoint",
                    "Office parent created a PowerShell child; command line is inert and redacted",
                )
            )
    return findings


def detect_rare_domain(events: list[Event], context: dict) -> list[Finding]:
    allowlist = set(context["known_benign"].get("known_domains", []))
    findings: list[Finding] = []
    for event in events:
        domain = str(event.attributes.get("Domain", ""))
        first_seen = bool(event.attributes.get("FirstSeen", False))
        rarity = int(event.attributes.get("BaselineCount", 0))
        if (
            event.source_type == "dns"
            and event.result == "Success"
            and domain not in allowlist
            and first_seen
            and rarity <= 1
        ):
            findings.append(
                _finding(
                    "DET009",
                    len(findings) + 1,
                    [event],
                    "low",
                    "medium",
                    "network",
                    f"Domain {domain} is new or rare for the device; "
                    "novelty alone is not malicious",
                )
            )
    return findings


DETECTORS: tuple[Detector, ...] = (
    detect_password_spray,
    detect_success_after_failures,
    detect_unusual_authentication,
    detect_phishing,
    detect_oauth_consent,
    detect_forwarding,
    detect_download_anomaly,
    detect_office_powershell,
    detect_rare_domain,
)


def run_detectors(events: list[Event], context: dict) -> list[Finding]:
    findings = [finding for detector in DETECTORS for finding in detector(events, context)]
    return sorted(findings, key=lambda item: (item.timestamp, item.detection_id, item.finding_id))
