from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from janus.models import GenerateRequest, SensorMode, TransportTrust
from janus.service import JanusService
from janus.wazuh import WazuhIndexerPoller, parse_wazuh_signal


def event(code: str, *, path: str | None = None, record: str = "1"):
    data = {
        "subjectDomainName": "LAB",
        "subjectUserName": "analyste",
        "subjectLogonId": "0xA11CE",
        "objectName": path,
        "processName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "processId": "0x420",
        "accessMask": "0x1",
        "accessList": "%%4416",
    }
    if code == "4688":
        data.update(
            {
                "targetDomainName": "LAB",
                "targetUserName": "analyste",
                "targetLogonId": "0xA11CE",
                "newProcessName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "newProcessId": "0x420",
                "parentProcessName": r"C:\Windows\explorer.exe",
                "commandLine": f'WINWORD.EXE "{path}"',
            }
        )
    return {
        "id": f"wazuh-{code}-{record}",
        "timestamp": datetime.now(UTC).isoformat(),
        "agent": {"id": "001", "name": "WIN-LAB"},
        "data": {
            "win": {
                "system": {
                    "eventID": code,
                    "computer": "WIN-LAB",
                    "eventRecordID": record,
                    "providerName": "Microsoft-Windows-Security-Auditing",
                },
                "eventdata": data,
            }
        },
    }


def test_4663_and_4688_same_logon_are_corroborated(settings):
    service = JanusService(settings)
    artifact = service.generate(
        GenerateRequest(theme="Finance", sensor_mode=SensorMode.LOCAL_PIXEL)
    )
    internal = service.database.get_artifact(artifact["id"])
    path = internal["deployment_path"]
    first = service.ingest_wazuh(event("4663", path=path), TransportTrust.VERIFIED)
    second = service.ingest_wazuh(event("4688", path=path, record="2"), TransportTrust.VERIFIED)
    assert first["artifact_id"] == artifact["id"]
    assert second["artifact_id"] == artifact["id"]
    correlated = [
        item
        for item in service.state()["events"]
        if item["event_code"] in {"4663", "4688"}
    ]
    assert {item["strength"] for item in correlated} == {"corroborated"}


def test_unknown_event_is_preserved_not_invented(settings):
    service = JanusService(settings)
    payload = event("9999", record="9999")
    result = service.ingest_wazuh(payload, TransportTrust.VERIFIED)
    assert result["normalized"] is False
    evidence = service.state()["events"][0]
    assert evidence["kind"] == "normalization_pending"
    assert evidence["strength"] == "unsupported"
    raw = service.database.raw_event(evidence["raw_event_id"])
    assert raw["payload"]["data"]["win"]["system"]["eventID"] == "9999"


def test_parser_keeps_4663_process_and_logon():
    signal = parse_wazuh_signal(event("4663", path=r"C:\JANUS\budget.docx"))
    assert signal.event_code == "4663"
    assert signal.logon_id == "0xA11CE"
    assert signal.process_name.endswith("WINWORD.EXE")
    assert signal.file_path.endswith("budget.docx")


def test_4663_and_sysmon_process_same_logon_are_corroborated(settings):
    service = JanusService(settings)
    artifact = service.generate(
        GenerateRequest(theme="Finance", sensor_mode=SensorMode.LOCAL_PIXEL)
    )
    internal = service.database.get_artifact(artifact["id"])
    service.ingest_wazuh(
        event("4663", path=internal["deployment_path"]),
        TransportTrust.VERIFIED,
    )
    sysmon = {
        "id": "sysmon-1-1",
        "timestamp": datetime.now(UTC).isoformat(),
        "agent": {"id": "001", "name": "WIN-LAB"},
        "data": {
            "win": {
                "system": {
                    "eventID": "1",
                    "computer": "WIN-LAB",
                    "eventRecordID": "3",
                    "providerName": "Microsoft-Windows-Sysmon",
                },
                "eventdata": {
                    "user": r"LAB\analyste",
                    "logonId": "0xA11CE",
                    "image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    "processId": "1056",
                    "processGuid": "{11111111-1111-1111-1111-111111111111}",
                    "commandLine": f'WINWORD.EXE "{internal["deployment_path"]}"',
                    "parentImage": r"C:\Windows\explorer.exe",
                },
            }
        },
    }

    linked = service.ingest_wazuh(sysmon, TransportTrust.VERIFIED)

    assert linked["artifact_id"] == artifact["id"]
    correlated = [
        item
        for item in service.state()["events"]
        if item["event_code"] in {"4663", "sysmon:1"}
    ]
    assert {item["strength"] for item in correlated} == {"corroborated"}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeIndexerSession:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return FakeResponse(self.pages.pop(0))


def test_indexer_collects_unknown_windows_events_and_paginates(settings):
    configured = replace(
        settings,
        wazuh_indexer_url="https://wazuh.example:9200",
        wazuh_indexer_username="janus",
        wazuh_indexer_password="secret",
    )
    first_hits = [
        {
            "_id": str(index),
            "sort": [f"2026-08-04T18:00:{index // 10:02d}.000Z", str(index)],
            "_source": {
                "timestamp": f"2026-08-04T18:00:{index // 10:02d}.000Z",
                "data": {"win": {"system": {"eventID": "9999"}}},
            },
        }
        for index in range(250)
    ]
    final_hit = {
        "_id": "250",
        "sort": ["2026-08-04T18:00:25.000Z", "250"],
        "_source": {
            "timestamp": "2026-08-04T18:00:25.000Z",
            "data": {"win": {"system": {"eventID": "9999"}}},
        },
    }
    session = FakeIndexerSession(
        [
            {"hits": {"hits": first_hits}},
            {"hits": {"hits": [final_hit]}},
        ]
    )
    ingested = []
    poller = WazuhIndexerPoller(
        configured,
        lambda payload, trust: ingested.append((payload, trust)),
        session=session,
    )

    assert poller.poll_once() == 251
    assert len(ingested) == 251
    first_filter = session.calls[0]["json"]["query"]["bool"]["filter"]
    assert {"exists": {"field": "data.win.system.eventID"}} in first_filter
    assert "terms" not in str(first_filter)
    assert session.calls[1]["json"]["search_after"] == first_hits[-1]["sort"]
