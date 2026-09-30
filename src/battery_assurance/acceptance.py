"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import timedelta
from pathlib import Path

from .clock import isoformat
from .disclosure import DisclosureService
from .jsonio import load_json
from .service import TrialService
from .storage import connect, inspect_schema


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="battery-assurance-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = TrialService(connection)
            disclosures = DisclosureService(connection, service.clock)
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("approver-1", "分析准入审批人", "approver")
            service.create_user("auditor-1", "审计人员", "auditor")
            service.register_asset("operator-1", "asset-a", "A 型人形储能电池资产", "示例厂商")
            service.register_evidence_revision("operator-1", "evidence_revision-a1", "asset-a", "1.0.0", "a" * 64)
            service.publish_protocol("stat-1", protocol)
            service.create_batch("operator-1", "batch-demo", protocol["protocol_id"], protocol["version"], "evidence_revision-a1")
            service.start_batch("operator-1", "batch-demo", 1)
            imported = service.import_observations(
                "operator-1", "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            report = service.report("auditor-1", "batch-demo")

            # 受众化披露：保险机构、维修承包商、二手受让方各取所需声明。
            passport = disclosures.issue_passport("operator-1", "passport-demo", "2026.09.1", "batch-demo")
            now = service.clock.now()
            valid_from = isoformat(now - timedelta(minutes=1))
            valid_until = isoformat(now + timedelta(days=30))
            insurer = disclosures.create_disclosure(
                "operator-1", "passport-demo", "insurer", "insurer-demo", "承保风险定价",
                ["asset_identity", "assessment_summary", "decision"],
                valid_from, valid_until,
            )
            repairer = disclosures.create_disclosure(
                "operator-1", "passport-demo", "repair_contractor", "repairer-demo", "制定维修方案",
                ["asset_identity", "capacity_metrics", "assessment_rules"],
                valid_from, valid_until,
            )
            buyer = disclosures.create_disclosure(
                "operator-1", "passport-demo", "secondary_buyer", "buyer-demo", "二手受让尽调",
                ["asset_identity", "evidence_provenance", "assessment_summary", "decision"],
                valid_from, valid_until, "full",
            )
            insurer_read = disclosures.read_disclosure(insurer["grant_token"])
            repairer_read = disclosures.read_disclosure(repairer["grant_token"])
            buyer_read = disclosures.read_disclosure(buyer["grant_token"])
            if len(insurer_read["envelope"]["statements"]) != 3:
                raise RuntimeError("保险机构披露包声明范围错误")
            if len(repairer_read["envelope"]["statements"]) != 3:
                raise RuntimeError("维修承包商披露包声明范围错误")
            if len(buyer_read["envelope"]["statements"]) != 4:
                raise RuntimeError("二手受让方披露包声明范围错误")
            # 同一申请重试必须返回原包。
            replayed = disclosures.create_disclosure(
                "operator-1", "passport-demo", "insurer", "insurer-demo", "承保风险定价",
                ["asset_identity", "assessment_summary", "decision"],
                valid_from, valid_until,
            )
            if not replayed["replayed"] or replayed["package_id"] != insurer["package_id"]:
                raise RuntimeError("同申请重试未返回原披露包")
            verification = disclosures.verify_package("auditor-1", insurer["package_id"])
            ledger = disclosures.disclosure_ledger("auditor-1")
            access = disclosures.access_report("auditor-1", insurer["package_id"])
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "passport_sha256": passport["sha256"],
        "disclosure_packages": len(ledger),
        "insurer_statement_count": len(insurer_read["envelope"]["statements"]),
        "disclosure_intact": verification["envelope_intact"],
        "insurer_access_events": len(access),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
