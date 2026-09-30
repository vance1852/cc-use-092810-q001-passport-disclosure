from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from battery_assurance.clock import FrozenClock
from battery_assurance.errors import Forbidden, InvalidState
from battery_assurance.jsonio import canonical_json, load_json
from battery_assurance.service import TrialService
from battery_assurance.disclosure import DisclosureService


ROOT = Path(__file__).resolve().parents[1]


class DisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        self.disclosure = DisclosureService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("custodian", "custodian"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text().splitlines()
            if line.strip()
        ]
        self.service.register_asset("operator", "asset-a", "A 型储能电池", "机密供应商")
        self.service.register_evidence_revision("operator", "ev-a", "asset-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "ev-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 60)
        self.analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide("approver", "batch-a", self.analysis["analysis_id"], "approved", "含供应合同价格的理由")
        self.passport = self.disclosure.issue_passport("custodian", "pp-a", 1, "batch-a")

    def tearDown(self) -> None:
        self.connection.close()

    def _create(self, *, audience_type="insurer", audience_id="ins-1", purpose="承保核保",
                claim_keys=("decision", "conclusion", "evidence_provenance"),
                hidden_fields=("vendor", "reason"), validity_seconds=3600, actor="custodian"):
        return self.disclosure.create_disclosure(actor, {
            "passport_id": "pp-a",
            "passport_version": 1,
            "audience_type": audience_type,
            "audience_id": audience_id,
            "purpose": purpose,
            "claim_keys": list(claim_keys),
            "hidden_fields": list(hidden_fields),
            "validity_seconds": validity_seconds,
        })

    def test_passport_requires_decided_batch(self) -> None:
        self.service.register_evidence_revision("operator", "ev-b", "asset-a", "2.0", "c" * 64)
        self.service.create_batch("operator", "batch-b", "demo-delivery-v1", 1, "ev-b")
        with self.assertRaises(InvalidState):
            self.disclosure.issue_passport("custodian", "pp-b", 1, "batch-b")
        self.assertEqual(self.passport["state"], "issued")
        self.assertEqual(len(self.passport["content_sha256"]), 64)

    def test_only_custodian_may_issue_or_disclose(self) -> None:
        from battery_assurance.errors import Forbidden as F
        with self.assertRaises(F):
            self.disclosure.issue_passport("operator", "pp-b", 1, "batch-a")
        with self.assertRaises(F):
            self._create(actor="auditor")

    def test_package_is_fixed_and_redacts_sensitive_field_but_keeps_evidence_chain(self) -> None:
        created = self._create()
        token = created["access_token"]
        delivered = self.disclosure.read_disclosure(token)
        package = delivered["package"]
        # 内容固定：接收方本地重算摘要与包摘要一致
        local_digest = hashlib.sha256(canonical_json(package).encode("utf-8")).hexdigest()
        self.assertEqual(local_digest, delivered["package_sha256"])
        # 时点可证明
        self.assertEqual(package["passport"]["passport_version"], 1)
        self.assertEqual(package["passport"]["content_sha256"], self.passport["content_sha256"])
        statements = {item["key"]: item for item in package["statements"]}
        self.assertEqual(set(statements), {"decision", "conclusion", "evidence_provenance"})
        # vendor 不在任何披露值中（供应合同信息隐藏）
        blob = canonical_json(package)
        self.assertNotIn("机密供应商", blob)
        # 决定理由未申请、不在包内
        self.assertNotIn("含供应合同价格的理由", blob)
        # 声明与原证据的可验证关联保留
        provenance = statements["evidence_provenance"]["value"]
        self.assertEqual(provenance["evidence_sha256"], "b" * 64)
        self.assertEqual(provenance["analysis_input_sha256"], self.analysis["input_sha256"])
        self.assertTrue(all(item["evidence"]["evidence_sha256"] == "b" * 64 for item in package["statements"]))
        # 包内没有可回到内部系统的记录句柄
        self.assertNotIn("batch_id", json.dumps(package, ensure_ascii=False))
        self.assertNotIn("internal", blob)

    def test_replay_returns_same_package_change_creates_new(self) -> None:
        first = self._create()
        replay = self._create()
        self.assertEqual(first["package_id"], replay["package_id"])
        self.assertEqual(first["package_sha256"], replay["package_sha256"])
        self.assertNotIn("access_token", replay)
        # 改变受众 → 新版本
        other_audience = self._create(audience_id="ins-2")
        self.assertNotEqual(first["package_id"], other_audience["package_id"])
        # 改变声明范围 → 新版本
        other_scope = self._create(audience_id="ins-1", claim_keys=("conclusion",))
        self.assertNotEqual(first["package_id"], other_scope["package_id"])
        # 改变目的 → 新版本
        other_purpose = self._create(audience_id="ins-1", purpose="理赔核查")
        self.assertNotEqual(first["package_id"], other_purpose["package_id"])
        # 改变期限 → 新版本
        other_ttl = self._create(audience_id="ins-1", validity_seconds=7200)
        self.assertNotEqual(first["package_id"], other_ttl["package_id"])

    def test_expiry_blocks_new_reads_but_history_remains(self) -> None:
        created = self._create(validity_seconds=60)
        self.disclosure.read_disclosure(created["access_token"])
        self.clock.advance(seconds=61)
        with self.assertRaises(Forbidden):
            self.disclosure.read_disclosure(created["access_token"])
        trail = self.disclosure.disclosure_trail("auditor", created["package_id"])
        results = [item["result"] for item in trail["accesses"]]
        self.assertEqual(results, ["delivered", "denied_expired"])
        self.assertEqual(trail["package"]["state"], "expired")

    def test_withdraw_blocks_immediately(self) -> None:
        created = self._create()
        self.disclosure.read_disclosure(created["access_token"])
        self.disclosure.withdraw_disclosure("custodian", created["package_id"], "合作终止")
        with self.assertRaises(Forbidden):
            self.disclosure.read_disclosure(created["access_token"])
        trail = self.disclosure.disclosure_trail("auditor", created["package_id"])
        self.assertEqual([item["result"] for item in trail["accesses"]], ["delivered", "denied_withdrawn"])

    def test_passport_revocation_cascades_to_packages(self) -> None:
        insurer = self._create(audience_id="ins-1")
        repairer = self._create(audience_type="repairer", audience_id="rep-1",
                                purpose="维修方案制定", claim_keys=("soh_estimate", "stratum_coverage"))
        self.disclosure.revoke_passport("custodian", "pp-a", 1, "评估依据有误")
        for token in (insurer["access_token"], repairer["access_token"]):
            with self.assertRaises(Forbidden):
                self.disclosure.read_disclosure(token)
        # 已交付摘要与访问事实继续留痕
        trail = self.disclosure.disclosure_trail("auditor", insurer["package_id"])
        self.assertIn("denied_revoked", [item["result"] for item in trail["accesses"]])
        # 吊销后不能再创建新披露
        with self.assertRaises(InvalidState):
            self._create(audience_id="ins-9")

    def test_invalid_token_and_audience_mismatch_are_denied_and_logged(self) -> None:
        created = self._create()
        with self.assertRaises(Forbidden):
            self.disclosure.read_disclosure("not-a-real-token")
        with self.assertRaises(Forbidden):
            self.disclosure.read_disclosure(created["access_token"], audience_id="someone-else")
        trail = self.disclosure.disclosure_trail("auditor", created["package_id"])
        self.assertEqual([item["result"] for item in trail["accesses"]], ["denied_token"])
        self.assertEqual(trail["accesses"][0]["audience_id"], "someone-else")

    def test_three_audiences_each_see_only_approved_claims(self) -> None:
        specs = [
            ("insurer", "ins-1", "承保", ("decision", "conclusion", "rule_results")),
            ("repairer", "rep-1", "维修", ("soh_estimate", "stratum_coverage", "sample_counts")),
            ("secondary_buyer", "buyer-1", "二手受让", ("passport_identity", "conclusion", "evidence_provenance")),
        ]
        for audience_type, audience_id, purpose, keys in specs:
            created = self._create(audience_type=audience_type, audience_id=audience_id,
                                   purpose=purpose, claim_keys=keys, hidden_fields=())
            package = self.disclosure.read_disclosure(created["access_token"])["package"]
            self.assertEqual({item["key"] for item in package["statements"]}, set(keys))
            self.assertEqual(package["audience"], {"type": audience_type, "id": audience_id})

    def test_verify_scope_detects_tampering(self) -> None:
        created = self._create()
        intact = self.disclosure.verify_disclosure_scope("auditor", created["package_id"])
        self.assertTrue(intact["within_scope"])
        self.assertTrue(intact["checks"]["statement_keys_equal_approval"])
        # 篡改冻结包内容 → 核验失败
        tampered = canonical_json({"extra": "unauthorized statement"})
        self.connection.execute(
            "UPDATE disclosure_packages SET package_json=? WHERE package_id=?",
            (tampered, created["package_id"]),
        )
        broken = self.disclosure.verify_disclosure_scope("auditor", created["package_id"])
        self.assertFalse(broken["within_scope"])
        self.assertFalse(broken["checks"]["projection_matches_frozen_package"])

    def test_auditor_can_answer_who_what_when(self) -> None:
        first = self._create(audience_id="ins-1", purpose="承保核保")
        second = self._create(audience_type="repairer", audience_id="rep-1",
                              purpose="维修方案", claim_keys=("soh_estimate",))
        self.disclosure.read_disclosure(first["access_token"])
        self.disclosure.read_disclosure(second["access_token"])
        listing = self.disclosure.list_disclosures("auditor", passport_id="pp-a")
        self.assertEqual({item["audience_id"] for item in listing}, {"ins-1", "rep-1"})
        trail = self.disclosure.disclosure_trail("auditor", second["package_id"])
        self.assertEqual(trail["package"]["purpose"], "维修方案")
        self.assertEqual(trail["accesses"][0]["result"], "delivered")
        self.assertIn("accessed_at", trail["accesses"][0])
        # 操作员无权查看合规视图
        with self.assertRaises(Forbidden):
            self.disclosure.list_disclosures("operator")

    def test_unknown_claim_or_field_rejected(self) -> None:
        with self.assertRaises(Exception):
            self._create(claim_keys=("not_a_claim",))
        with self.assertRaises(Exception):
            self.disclosure.create_disclosure("custodian", {
                "passport_id": "pp-a", "passport_version": 1,
                "audience_type": "insurer", "audience_id": "ins-1", "purpose": "x",
                "claim_keys": ["conclusion"], "hidden_fields": ["contract_price"],
                "validity_seconds": 60,
            })


if __name__ == "__main__":
    unittest.main()
