from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from battery_assurance.api import JsonApplication
from battery_assurance.clock import FrozenClock, isoformat
from battery_assurance.jsonio import load_json
from battery_assurance.service import TrialService
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _post(app, path, payload, actor=None, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if actor:
        headers["X-Actor-Id"] = actor
    if extra_headers:
        headers.update(extra_headers)
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return app.handle("POST", path, headers, body)


def _get(app, path, actor=None, headers=None):
    head = {"X-Actor-Id": actor} if actor else {}
    if headers:
        head.update(headers)
    return app.handle("GET", path, head, b"")


class DisclosureApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        service = TrialService(self.connection, self.clock)
        self.app = JsonApplication(service)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            service.create_user(user_id, user_id, role)
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        service.register_asset("operator", "asset-a", "A 型", "机密供应商")
        service.register_evidence_revision("operator", "evidence-a", "asset-a", "1.0", "b" * 64)
        service.publish_protocol("stat", protocol)
        service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "evidence-a")
        service.start_batch("operator", "batch-a", 1)
        service.import_observations("operator", "batch-a", "k1", rows)
        service.seal_batch("stat", "batch-a", 2)
        job = service.claim_job("worker", 30)
        analysis = service.complete_job("worker", job["job_id"], "stat")
        service.decide("approver", "batch-a", analysis["analysis_id"], "approved", "合同价 8 折")
        self.valid_from = isoformat(self.clock.now() - timedelta(minutes=1))
        self.valid_until = isoformat(self.clock.now() + timedelta(days=7))

    def tearDown(self) -> None:
        self.connection.close()

    def test_full_disclosure_flow_over_http(self) -> None:
        issued = _post(self.app, "/passports", {
            "passport_id": "p1", "passport_version": "1.0.0", "batch_id": "batch-a",
        }, actor="operator")
        self.assertEqual(issued.status, 201)

        payload = {
            "passport_id": "p1",
            "audience_type": "insurer",
            "audience_ref": "insurer-http",
            "purpose": "承保",
            "statement_keys": ["asset_identity", "decision"],
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }
        created = _post(self.app, "/disclosures", payload, actor="operator")
        self.assertEqual(created.status, 201)
        package_id = created.body["package_id"]
        token = created.body["grant_token"]
        self.assertIsNotNone(token)

        # 重试返回原包，不重新下发凭证。
        replay = _post(self.app, "/disclosures", payload, actor="operator")
        self.assertEqual(replay.status, 201)
        self.assertTrue(replay.body["replayed"])
        self.assertIsNone(replay.body["grant_token"])
        self.assertEqual(replay.body["package_id"], package_id)

        read = _post(self.app, "/disclosures/read", {"grant_token": token, "audience_ref": "insurer-http"})
        self.assertEqual(read.status, 200)
        statements = {s["statement_key"]: s for s in read.body["envelope"]["statements"]}
        self.assertEqual(statements["asset_identity"]["visible"]["vendor"], "***REDACTED***")
        self.assertEqual(statements["decision"]["visible"]["reason"], "***REDACTED***")
        self.assertEqual(read.body["verification"]["package_sha256"], created.body["content_sha256"])
        self.assertNotIn("合同价", json.dumps(read.body, ensure_ascii=False))

        verify = _get(self.app, f"/disclosures/{package_id}/verify", actor="auditor")
        self.assertEqual(verify.status, 200)
        self.assertTrue(verify.body["envelope_intact"])

        ledger = _get(self.app, "/disclosures/ledger", actor="auditor")
        self.assertEqual(ledger.status, 200)
        self.assertEqual(len(ledger.body["packages"]), 1)
        self.assertEqual(ledger.body["packages"][0]["audience"]["ref"], "insurer-http")

        access = _get(self.app, "/disclosures/access", actor="auditor")
        self.assertEqual(access.status, 200)
        self.assertEqual([e["result"] for e in access.body["events"]], ["served"])

        # 撤回后新读取立即 403，访问事实继续留痕。
        withdrawn = _post(self.app, f"/disclosures/{package_id}/withdraw", {"reason": "终止"}, actor="operator")
        self.assertEqual(withdrawn.status, 200)
        denied = _post(self.app, "/disclosures/read", {"grant_token": token})
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.body["error"]["code"], "forbidden")
        access2 = _get(self.app, "/disclosures/access", actor="auditor")
        self.assertEqual([e["result"] for e in access2.body["events"]], ["served", "denied_withdrawn"])

    def test_auditor_cannot_create_disclosure(self) -> None:
        _post(self.app, "/passports", {
            "passport_id": "p1", "passport_version": "1.0.0", "batch_id": "batch-a",
        }, actor="operator")
        response = _post(self.app, "/disclosures", {
            "passport_id": "p1", "audience_type": "insurer", "audience_ref": "x",
            "purpose": "p", "statement_keys": ["decision"],
            "valid_from": self.valid_from, "valid_until": self.valid_until,
        }, actor="auditor")
        self.assertEqual(response.status, 403)

    def test_read_with_bogus_token_is_404_and_logged(self) -> None:
        response = _post(self.app, "/disclosures/read", {"grant_token": "nope"})
        self.assertEqual(response.status, 404)
        access = _get(self.app, "/disclosures/access", actor="auditor")
        self.assertEqual(access.body["events"][-1]["result"], "denied_unknown_token")


if __name__ == "__main__":
    unittest.main()
