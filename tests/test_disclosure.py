from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from battery_assurance.clock import FrozenClock, isoformat
from battery_assurance.errors import Forbidden, InvalidState, NotFound
from battery_assurance.jsonio import canonical_json, content_digest, load_json
from battery_assurance.disclosure import DisclosureService
from battery_assurance.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class DisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        self.disclosures = DisclosureService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_asset("operator", "asset-a", "A 型储能电池", "机密供应商股份公司")
        self.service.register_evidence_revision("operator", "evidence-a", "asset-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "evidence-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        self.analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide("approver", "batch-a", self.analysis["analysis_id"], "approved", "内部供应合同折扣价 8 折")
        self.passport = self.disclosures.issue_passport(
            "operator", "passport-a", "1.0.0", "batch-a"
        )
        self.valid_from = isoformat(self.clock.now())
        self.valid_until = isoformat(self.clock.now() + timedelta(days=7))
        self.all_statements = sorted([
            "asset_identity", "evidence_provenance", "assessment_summary",
            "assessment_rules", "capacity_metrics", "decision",
        ])

    def tearDown(self) -> None:
        self.connection.close()

    def _create(self, *, audience_ref="insurer-picc", purpose="承保核保",
                statements=None, audience_type="insurer", policy="mask_commercial"):
        return self.disclosures.create_disclosure(
            "operator", "passport-a", audience_type, audience_ref, purpose,
            statements or self.all_statements, self.valid_from, self.valid_until, policy,
        )

    # ------------------------------------------------------------ 签发与权限

    def test_passport_requires_decided_batch(self) -> None:
        self.service.create_batch("operator", "batch-b", "demo-delivery-v1", 1, "evidence-a")
        with self.assertRaises(InvalidState):
            self.disclosures.issue_passport("operator", "passport-b", "1.0.0", "batch-b")

    def test_only_asset_owner_role_can_issue_and_create(self) -> None:
        with self.assertRaises(Forbidden):
            self.disclosures.issue_passport("stat", "passport-x", "1.0.0", "batch-a")
        with self.assertRaises(Forbidden):
            self.disclosures.create_disclosure(
                "auditor", "passport-a", "insurer", "x", "p", ["decision"],
                self.valid_from, self.valid_until,
            )

    def test_passport_content_is_fixed_and_digested(self) -> None:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM passports WHERE passport_id='passport-a'"
        ).fetchone()
        recomputed = hashlib.sha256(row["canonical_json"].encode("utf-8")).hexdigest()
        self.assertEqual(recomputed, row["content_sha256"])
        self.assertEqual(self.passport["sha256"], row["content_sha256"])

    # ------------------------------------------------------------ 脱敏与锚点

    def test_sensitive_fields_redacted_but_verifiable_link_kept(self) -> None:
        package = self._create()
        token = package["grant_token"]
        read = self.disclosures.read_disclosure(token)
        statements = {s["statement_key"]: s for s in read["envelope"]["statements"]}

        identity = statements["asset_identity"]
        self.assertEqual(identity["visible"]["vendor"], "***REDACTED***")
        self.assertEqual(identity["visible"]["asset_id"], "asset-a")
        self.assertIn("vendor", identity["redacted_fields"])
        self.assertEqual(set(identity["source"]), {"record", "locator", "sha256"})
        self.assertEqual(identity["source"]["record"], "battery_assets")
        self.assertEqual(len(identity["source"]["sha256"]), 64)

        decision = statements["decision"]
        self.assertEqual(decision["visible"]["decision"], "approved")
        self.assertEqual(decision["visible"]["reason"], "***REDACTED***")
        self.assertEqual(decision["source"]["record"], "decisions")

        # 包内序列化结果不包含任何敏感原文，引用中也没有可读业务字段。
        serialized = canonical_json(read)
        self.assertNotIn("机密供应商股份公司", serialized)
        self.assertNotIn("内部供应合同折扣价", serialized)
        for statement in read["envelope"]["statements"]:
            self.assertEqual(set(statement["source"]), {"record", "locator", "sha256"})

        # 锚点摘要与原始记录实际摘要一致，证明声明来自该时点的原证据。
        asset_row = self.connection.execute(
            "SELECT asset_id,model_name,vendor,created_at FROM battery_assets WHERE asset_id='asset-a'"
        ).fetchone()
        self.assertEqual(identity["source"]["sha256"], content_digest([dict(asset_row)]))

    def test_full_policy_discloses_no_extra_records(self) -> None:
        package = self._create(policy="full", audience_ref="buyer-1", purpose="二手受让尽调")
        read = self.disclosures.read_disclosure(package["grant_token"])
        statements = {s["statement_key"]: s for s in read["envelope"]["statements"]}
        self.assertEqual(statements["decision"]["visible"]["reason"], "内部供应合同折扣价 8 折")
        self.assertEqual(statements["decision"]["redacted_fields"], [])
        # 即使不脱敏，锚点依旧只有定位符与摘要，不能凭包读取原始记录。
        self.assertEqual(set(statements["decision"]["source"]), {"record", "locator", "sha256"})

    def test_statement_subset_limits_scope(self) -> None:
        package = self._create(statements=["assessment_summary"], audience_ref="repair-1")
        read = self.disclosures.read_disclosure(package["grant_token"])
        self.assertEqual([s["statement_key"] for s in read["envelope"]["statements"]], ["assessment_summary"])
        serialized = canonical_json(read)
        self.assertNotIn("approved", serialized)
        self.assertNotIn("机密供应商", serialized)

    def test_unknown_statement_rejected(self) -> None:
        with self.assertRaises(Exception):
            self._create(statements=["decision", "supply_contract_price"])

    # ------------------------------------------------------------ 幂等与版本

    def test_same_request_replays_original_package(self) -> None:
        first = self._create()
        second = self._create()
        self.assertTrue(second["replayed"])
        self.assertIsNone(second["grant_token"])
        self.assertEqual(second["package_id"], first["package_id"])
        self.assertEqual(second["package_version"], first["package_version"])
        self.assertEqual(second["content_sha256"], first["content_sha256"])
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM disclosure_packages").fetchone()[0], 1
        )

    def test_changed_audience_or_scope_creates_new_version(self) -> None:
        first = self._create(audience_ref="insurer-picc")
        second = self._create(audience_ref="insurer-pingan")
        self.assertFalse(second["replayed"])
        self.assertEqual(first["package_version"], 1)
        self.assertEqual(second["package_version"], 2)
        self.assertNotEqual(first["package_id"], second["package_id"])

        third = self._create(
            audience_ref="insurer-picc", statements=["assessment_summary", "decision"]
        )
        self.assertEqual(third["package_version"], 3)

    # ------------------------------------------------------------ 失效与留痕

    def test_expiry_blocks_new_reads_but_keeps_history(self) -> None:
        package = self._create()
        read = self.disclosures.read_disclosure(package["grant_token"])
        self.assertEqual(read["verification"]["statement_count"], 6)
        self.clock.advance(days=8)
        with self.assertRaises(Forbidden):
            self.disclosures.read_disclosure(package["grant_token"])
        events = self.disclosures.access_report("auditor", package["package_id"])
        self.assertEqual([e["result"] for e in events], ["served", "denied_expired"])
        self.assertEqual(events[0]["audience_ref"], "insurer-picc")
        self.assertEqual(events[0]["purpose"], "承保核保")
        self.assertEqual(events[0]["statement_keys"], self.all_statements)

    def test_withdrawal_blocks_new_reads_immediately(self) -> None:
        package = self._create()
        self.disclosures.read_disclosure(package["grant_token"])
        self.disclosures.withdraw_package("operator", package["package_id"], "合作终止")
        with self.assertRaises(Forbidden):
            self.disclosures.read_disclosure(package["grant_token"])
        events = self.disclosures.access_report("auditor", package["package_id"])
        self.assertEqual([e["result"] for e in events], ["served", "denied_withdrawn"])
        # 已交付摘要仍可核验
        verification = self.disclosures.verify_package("auditor", package["package_id"])
        self.assertTrue(verification["envelope_intact"])

    def test_passport_revocation_blocks_all_packages(self) -> None:
        package = self._create()
        self.disclosures.read_disclosure(package["grant_token"])
        self.disclosures.revoke_passport("operator", "passport-a", "证据存在重大错误")
        with self.assertRaises(Forbidden):
            self.disclosures.read_disclosure(package["grant_token"])
        with self.assertRaises(InvalidState):
            self._create(audience_ref="insurer-other")
        replay = self._create()
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["package_id"], package["package_id"])
        self.assertEqual(replay["effective_status"], "passport_revoked")
        events = self.disclosures.access_report("auditor", package["package_id"])
        self.assertEqual(events[-1]["result"], "denied_revoked")
        self.assertEqual(self.disclosures.disclosure_ledger("auditor")[0]["effective_status"], "passport_revoked")

    def test_unknown_token_denied_and_logged(self) -> None:
        self._create()
        with self.assertRaises(NotFound):
            self.disclosures.read_disclosure("deadbeef")
        events = self.disclosures.access_report("auditor")
        self.assertEqual(events[-1]["result"], "denied_unknown_token")

    def test_each_successful_read_is_recorded(self) -> None:
        package = self._create()
        self.disclosures.read_disclosure(package["grant_token"])
        self.disclosures.read_disclosure(package["grant_token"])
        events = self.disclosures.access_report("auditor", package["package_id"])
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e["result"] == "served" for e in events))

    # ------------------------------------------------------------ 完整性核验

    def test_package_envelope_hash_is_stable_and_claims_anchor_to_sources(self) -> None:
        package = self._create()
        read = self.disclosures.read_disclosure(package["grant_token"])
        envelope = read["envelope"]
        recomputed = hashlib.sha256(
            canonical_json(envelope).encode("utf-8")
        ).hexdigest()
        self.assertEqual(recomputed, package["content_sha256"])
        self.assertEqual(read["verification"]["package_sha256"], package["content_sha256"])
        self.assertEqual(read["verification"]["passport_sha256"], self.passport["sha256"])

        verification = self.disclosures.verify_package("operator", package["package_id"])
        self.assertTrue(verification["envelope_intact"])
        self.assertEqual(len(verification["claims"]), 6)
        self.assertTrue(all(item["claim_sha256_ok"] for item in verification["claims"]))
        self.assertTrue(all(item["source_anchor_ok"] for item in verification["claims"]))

    def test_auditor_can_answer_who_what_when_and_scope_bound(self) -> None:
        package = self._create(statements=["decision"], audience_ref="buyer-2", purpose="二手交易定价")
        self.disclosures.read_disclosure(package["grant_token"])
        ledger = self.disclosures.disclosure_ledger("auditor")
        self.assertEqual(len(ledger), 1)
        entry = ledger[0]
        self.assertEqual(entry["audience"], {"type": "insurer", "ref": "buyer-2"})
        self.assertEqual(entry["purpose"], "二手交易定价")
        self.assertEqual(entry["statement_keys"], ["decision"])
        self.assertEqual(entry["effective_status"], "active")
        self.assertEqual(entry["content_sha256"], package["content_sha256"])

        with self.assertRaises(Forbidden):
            self.disclosures.disclosure_ledger("stat")
        with self.assertRaises(Forbidden):
            self.disclosures.access_report("approver")

    def test_replay_after_withdrawal_stays_withdrawn(self) -> None:
        first = self._create()
        self.disclosures.withdraw_package("operator", first["package_id"], "误发")
        replay = self._create()
        self.assertEqual(replay["package_id"], first["package_id"])
        self.assertEqual(replay["effective_status"], "withdrawn")


if __name__ == "__main__":
    unittest.main()
