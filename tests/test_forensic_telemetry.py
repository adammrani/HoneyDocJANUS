"""Tests du modèle de télémétrie JANUS Windows/Linux."""

import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.detection.forensic_collector import (  # noqa: E402
    ForensicCollector,
    ForensicCollectorConfig,
)
from janus_v2.correlation.attack_timeline import build_attack_timeline  # noqa: E402
from janus_v2.domain.signals import ObservedAction, SignalKind  # noqa: E402
from janus_v2.registry.security_signal_store import (  # noqa: E402
    SqliteSecuritySignalStore,
)
from janus_v2.telemetry.signal_adapter import parse_wazuh_signal  # noqa: E402
from janus_v2.telemetry.wazuh_indexer_client import (  # noqa: E402
    WazuhAlertPage,
    WazuhIndexerClient,
)


def windows_alert(event_id, eventdata, *, provider="Microsoft-Windows-Security-Auditing"):
    return {
        "_id": f"win-{event_id}",
        "_source": {
            "id": f"evt-{event_id}",
            "timestamp": "2026-07-28T10:15:30.000+0000",
            "agent": {"id": "001", "name": "JANUS-WINDOWS"},
            "data": {
                "win": {
                    "system": {
                        "eventID": str(event_id),
                        "eventRecordID": f"90{event_id}",
                        "computer": "DESKTOP-LAB",
                        "providerName": provider,
                    },
                    "eventdata": eventdata,
                }
            },
        },
        "sort": [1785233730000, f"win-{event_id}"],
    }


def linux_alert():
    return {
        "_id": "linux-exec-1",
        "_source": {
            "id": "1785233730.1",
            "timestamp": "2026-07-28T10:15:30.000+0000",
            "agent": {"id": "007", "name": "ubuntu-lab"},
            "data": {
                "audit": {
                    "type": "SYSCALL",
                    "id": "1753697730.42:101",
                    "syscall": "59",
                    "key": "audit-wazuh-c",
                    "auid": "1000",
                    "uid": "0",
                    "euid": "0",
                    "session": "14",
                    "tty": "pts0",
                    "pid": "2811",
                    "ppid": "2790",
                    "exe": "/usr/bin/sudo",
                    "cwd": "/home/alice",
                    "execve": {"a0": "sudo", "a1": "cat", "a2": "/etc/shadow"},
                }
            },
        },
        "sort": [1785233730001, "linux-exec-1"],
    }


class SignalAdapterTests(unittest.TestCase):
    def test_4663_distinguishes_read_modify_and_delete(self):
        common = {
            "subjectUserName": "alice",
            "subjectDomainName": "LAB",
            "objectName": r"C:\JANUS\data\shared\budget.xlsx",
            "processName": r"C:\Program Files\Microsoft Office\EXCEL.EXE",
        }
        cases = [
            ("0x1", "%%4416", ObservedAction.READ),
            ("0x2", "%%4417", ObservedAction.MODIFY),
            ("0x10000", "%%1537", ObservedAction.DELETE),
        ]
        for mask, access, expected in cases:
            signal = parse_wazuh_signal(
                windows_alert("4663", {**common, "accessMask": mask, "accessList": access})
            )
            self.assertEqual(signal.action, expected)
        self.assertIn("office_open_candidate", signal.tags if expected == ObservedAction.DELETE else ())

    def test_4624_preserves_entry_point_and_localhost(self):
        signal = parse_wazuh_signal(
            windows_alert(
                "4624",
                {
                    "targetUserName": "alice",
                    "targetDomainName": "LAB",
                    "targetUserSid": "S-1-5-21-1000",
                    "targetLogonId": "0xabc",
                    "logonType": "10",
                    "ipAddress": "127.0.0.1",
                    "ipPort": "54421",
                },
            )
        )
        self.assertEqual(signal.kind, SignalKind.LOGON)
        self.assertEqual(signal.entry_channel, "rdp")
        self.assertEqual(signal.source_ip, "127.0.0.1")

    def test_5145_remote_read_has_ip_and_path(self):
        signal = parse_wazuh_signal(
            windows_alert(
                "5145",
                {
                    "subjectUserName": "bob",
                    "subjectDomainName": "LAB",
                    "ipAddress": "10.10.20.44",
                    "ipPort": "53111",
                    "relativeTargetName": r"finance\budget.xlsx",
                    "accessMask": "0x1",
                    "accessList": "%%4416",
                },
            )
        )
        self.assertEqual(signal.kind, SignalKind.REMOTE_FILE_ACCESS)
        self.assertEqual(signal.action, ObservedAction.READ)
        self.assertEqual(signal.source_ip, "10.10.20.44")

    def test_4688_and_sysmon_keep_command_network_and_dns(self):
        process = parse_wazuh_signal(
            windows_alert(
                "4688",
                {
                    "subjectUserName": "alice",
                    "newProcessName": r"C:\Windows\System32\curl.exe",
                    "newProcessId": "0x1234",
                    "commandLine": "curl.exe http://server/budget.xlsx",
                    "parentProcessName": r"C:\Windows\System32\cmd.exe",
                },
            )
        )
        self.assertIn("budget.xlsx", process.command_line)

        network = parse_wazuh_signal(
            windows_alert(
                "3",
                {
                    "image": r"C:\Windows\System32\curl.exe",
                    "sourceIp": "10.0.0.12",
                    "sourcePort": "53000",
                    "destinationIp": "10.0.0.20",
                    "destinationPort": "8000",
                },
                provider="Microsoft-Windows-Sysmon",
            )
        )
        self.assertEqual(network.kind, SignalKind.NETWORK_CONNECTION)
        self.assertEqual(network.destination_port, "8000")

        dns = parse_wazuh_signal(
            windows_alert(
                "22",
                {"image": r"C:\Windows\System32\curl.exe", "queryName": "decoy.lab"},
                provider="Microsoft-Windows-Sysmon",
            )
        )
        self.assertEqual(dns.query_name, "decoy.lab")

    def test_linux_audit_reconstructs_bash_related_execve(self):
        signal = parse_wazuh_signal(linux_alert())
        self.assertEqual(signal.kind, SignalKind.COMMAND_EXECUTION)
        self.assertEqual(signal.command_line, "sudo cat /etc/shadow")
        self.assertEqual(signal.audit_user_id, "1000")
        self.assertEqual(signal.effective_user_id, "0")
        self.assertEqual(signal.terminal, "pts0")
        self.assertEqual(signal.working_directory, "/home/alice")


class SignalStoreAndCollectorTests(unittest.TestCase):
    def test_store_deduplicates_and_filters(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SqliteSecuritySignalStore(Path(temp) / "janus.db")
            store.initialize()
            alert = linux_alert()
            signal = parse_wazuh_signal(alert)
            self.assertTrue(store.record(alert, signal))
            self.assertFalse(store.record(alert, signal))
            self.assertEqual(store.count(), 1)
            rows = store.list_signals(platform="linux", kind="command_execution")
            self.assertEqual(rows[0]["command_line"], "sudo cat /etc/shadow")
            timeline = store.list_timeline(logon_id="14", hostname="ubuntu-lab")
            self.assertEqual(len(timeline), 1)

    def test_timeline_exposes_only_an_observed_entry_point(self):
        logon = parse_wazuh_signal(
            windows_alert(
                "4624",
                {
                    "targetUserName": "alice",
                    "targetLogonId": "0xabc",
                    "logonType": "3",
                    "ipAddress": "10.0.0.40",
                },
            )
        ).to_dict()
        read = parse_wazuh_signal(
            windows_alert(
                "4663",
                {
                    "subjectUserName": "alice",
                    "subjectLogonId": "0xabc",
                    "objectName": r"C:\JANUS\data\shared\budget.xlsx",
                    "accessMask": "0x1",
                    "accessList": "%%4416",
                },
            )
        ).to_dict()
        timeline = build_attack_timeline([read, logon])
        self.assertEqual(timeline["entry_point"]["source_ip"], "10.0.0.40")
        self.assertEqual(timeline["entry_point"]["channel"], "network")
        self.assertEqual(timeline["step_count"], 2)

    def test_collector_persists_windows_and_linux(self):
        class Source:
            def __init__(self):
                self.calls = []

            def fetch_forensic_signals(self, **kwargs):
                self.calls.append(kwargs)
                return WazuhAlertPage(
                    alerts=[
                        windows_alert("4624", {"targetUserName": "alice", "logonType": "3"}),
                        linux_alert(),
                    ],
                    next_search_after=[1785233730001, "linux-exec-1"],
                )

        with tempfile.TemporaryDirectory() as temp:
            store = SqliteSecuritySignalStore(Path(temp) / "janus.db")
            store.initialize()
            source = Source()
            collector = ForensicCollector(
                source=source,
                store=store,
                config=ForensicCollectorConfig(batch_size=200),
                clock_epoch_ms=lambda: 1785233800000,
            )
            self.assertEqual(collector.run_once(), 2)
            self.assertEqual(store.count(), 2)
            self.assertEqual(collector.status()["last_batch_linux"], 1)
            self.assertIn("audit-wazuh-c", source.calls[0]["audit_keys"])

    def test_collector_ignores_service_logons(self):
        class Source:
            def fetch_forensic_signals(self, **kwargs):
                return WazuhAlertPage(
                    alerts=[
                        windows_alert(
                            "4624",
                            {
                                "targetUserName": "SYSTEM",
                                "targetDomainName": "NT AUTHORITY",
                                "targetLogonId": "0x3e7",
                                "logonType": "5",
                            },
                        )
                    ],
                    next_search_after=[1785233730000, "win-4624"],
                )

        with tempfile.TemporaryDirectory() as temp:
            store = SqliteSecuritySignalStore(Path(temp) / "janus.db")
            store.initialize()
            collector = ForensicCollector(
                source=Source(),
                store=store,
                config=ForensicCollectorConfig(batch_size=200),
                clock_epoch_ms=lambda: 1785233800000,
            )
            self.assertEqual(collector.run_once(), 0)
            self.assertEqual(store.count(), 0)
            self.assertEqual(collector.status()["last_batch_ignored"], 1)


class ForensicIndexerQueryTests(unittest.TestCase):
    def test_query_combines_event_ids_audit_keys_and_agents(self):
        captured = {}

        def transport(request, context, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return {"hits": {"hits": []}}

        client = WazuhIndexerClient(
            base_url="https://localhost:9200",
            username="janus",
            password="secret",
            verify_ssl=False,
            transport=transport,
        )
        client.fetch_forensic_signals(
            windows_event_ids=("4624", "4663"),
            audit_keys=("audit-wazuh-c",),
            agent_ids=("001", "007"),
            since_epoch_ms=1000,
            until="now-3s",
            batch_size=100,
        )
        query = captured["body"]["query"]["bool"]
        self.assertEqual(query["minimum_should_match"], 1)
        self.assertIn({"terms": {"agent.id": ["001", "007"]}}, query["filter"])
        self.assertIn(
            {"terms": {"data.audit.key": ["audit-wazuh-c"]}}, query["should"]
        )


if __name__ == "__main__":
    unittest.main()
