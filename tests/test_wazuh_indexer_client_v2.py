"""Tests du client HTTP Wazuh Indexer."""

import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.telemetry.wazuh_indexer_client import (  # noqa: E402
    WazuhIndexerClient,
)


class WazuhIndexerClientTests(unittest.TestCase):
    def test_query_uses_rule_range_and_stable_pagination(self) -> None:
        captured = {}

        def transport(request, context, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            captured["authorization"] = request.headers["Authorization"]
            return {
                "hits": {
                    "hits": [
                        {"_id": "a", "_source": {}, "sort": [1000, "a"]},
                        {"_id": "b", "_source": {}, "sort": [1001, "b"]},
                    ]
                }
            }

        client = WazuhIndexerClient(
            base_url="https://localhost:9200/",
            username="janus",
            password="secret",
            verify_ssl=False,
            timeout_seconds=7,
            transport=transport,
        )

        page = client.fetch_alerts(
            rule_id="100100",
            since_epoch_ms=900,
            until="now-3s",
            batch_size=2,
            search_after=[899, "previous"],
        )

        self.assertEqual(len(page.alerts), 2)
        self.assertEqual(page.next_search_after, [1001, "b"])
        self.assertEqual(captured["timeout"], 7)
        self.assertTrue(captured["authorization"].startswith("Basic "))
        self.assertNotIn("secret", captured["authorization"])
        self.assertTrue(captured["url"].endswith("/wazuh-alerts-4.x-*/_search"))

        body = captured["body"]
        self.assertEqual(body["size"], 2)
        self.assertEqual(body["search_after"], [899, "previous"])
        filters = body["query"]["bool"]["filter"]
        self.assertEqual(filters[0], {"term": {"rule.id": "100100"}})
        self.assertEqual(
            filters[1]["range"]["timestamp"]["gte"],
            900,
        )


if __name__ == "__main__":
    unittest.main()
