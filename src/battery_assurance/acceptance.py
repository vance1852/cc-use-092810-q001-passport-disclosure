"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .jsonio import load_json
from .disclosure import DisclosureService
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
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("approver-1", "分析准入审批人", "approver")
            service.create_user("custodian-1", "资产责任方", "custodian")
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
            disclosures = DisclosureService(connection, service.clock)
            passport = disclosures.issue_passport("custodian-1", "passport-demo", 1, "batch-demo")
            insurer_pkg = disclosures.create_disclosure("custodian-1", {
                "passport_id": "passport-demo",
                "passport_version": 1,
                "audience_type": "insurer",
                "audience_id": "insurer-demo",
                "purpose": "承保核保",
                "claim_keys": ["decision", "conclusion", "rule_results", "evidence_provenance"],
                "hidden_fields": ["vendor", "reason"],
                "validity_seconds": 86400,
            })
            repairer_pkg = disclosures.create_disclosure("custodian-1", {
                "passport_id": "passport-demo",
                "passport_version": 1,
                "audience_type": "repairer",
                "audience_id": "repairer-demo",
                "purpose": "维修方案制定",
                "claim_keys": ["soh_estimate", "stratum_coverage", "sample_counts"],
                "hidden_fields": ["vendor", "reason"],
                "validity_seconds": 86400,
            })
            buyer_pkg = disclosures.create_disclosure("custodian-1", {
                "passport_id": "passport-demo",
                "passport_version": 1,
                "audience_type": "secondary_buyer",
                "audience_id": "buyer-demo",
                "purpose": "二手受让尽调",
                "claim_keys": ["passport_identity", "conclusion", "evidence_provenance"],
                "hidden_fields": ["vendor", "reason"],
                "validity_seconds": 86400,
            })
            # 同一申请重试返回原包
            insurer_replay = disclosures.create_disclosure("custodian-1", {
                "passport_id": "passport-demo", "passport_version": 1,
                "audience_type": "insurer", "audience_id": "insurer-demo", "purpose": "承保核保",
                "claim_keys": ["decision", "conclusion", "rule_results", "evidence_provenance"],
                "hidden_fields": ["vendor", "reason"], "validity_seconds": 86400,
            })
            insurer_view = disclosures.read_disclosure(insurer_pkg["access_token"], "insurer-demo")
            scope_check = disclosures.verify_disclosure_scope("auditor-1", insurer_pkg["package_id"])
            trail = disclosures.disclosure_trail("auditor-1", insurer_pkg["package_id"])
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
        "passport_sha256": passport["content_sha256"],
        "disclosure_count": 3,
        "replay_same_package": insurer_replay["package_id"] == insurer_pkg["package_id"],
        "insurer_statement_keys": [item["key"] for item in insurer_view["package"]["statements"]],
        "disclosure_within_scope": scope_check["within_scope"],
        "disclosure_access_results": [item["result"] for item in trail["accesses"]],
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
