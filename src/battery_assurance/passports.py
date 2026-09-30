"""电池护照与受众化披露包的领域逻辑。

护照是评估事实在某一时点的不可变快照；披露包是对护照快照按受众、
目的、声明范围与敏感字段策略投影后得到的固定内容。投影只携带被批准
声明的原文与原证据摘要，不包含任何可回到内部系统读取未授权记录的句
柄，因此包内容可以整体计算摘要并离线核验。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import ValidationError


AUDIENCE_TYPES = frozenset({"insurer", "repairer", "secondary_buyer"})

# 护照可对外披露的声明目录。键即披露申请中 claim_keys 可引用的稳定标识。
CLAIM_CATALOG: dict[str, str] = {
    "asset_identity": "资产标识与型号",
    "passport_identity": "护照版本与签发时点",
    "decision": "准入决定与理由",
    "conclusion": "总体评估结论",
    "soh_estimate": "健康状态估计（加权均值）",
    "rule_results": "逐条准入规则的阈值与实测结果",
    "stratum_coverage": "各校准分层的样本覆盖情况",
    "sample_counts": "纳入与排除样本数量",
    "evidence_provenance": "证据版本与评估输入的摘要链",
}

# 声明值中的敏感字段（供应合同等商业信息），命中后按策略隐藏。
SENSITIVE_FIELDS = frozenset({"vendor", "reason"})


@dataclass(frozen=True, slots=True)
class Claim:
    """一条可披露声明：固定内容加原证据关联。"""

    key: str
    label: str
    value: Any
    evidence: Mapping[str, Any]


def _metric_soh(protocol: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    aggregate = result.get("aggregate", {})
    items = []
    for metric_key, metric in aggregate.items():
        if isinstance(metric, Mapping) and metric.get("available"):
            items.append({"metric": metric_key, "weighted_mean": metric.get("weighted_mean")})
    return {"metrics": items}


def build_passport_content(
    *,
    passport_id: str,
    passport_version: int,
    asset: Mapping[str, Any],
    evidence_revision: Mapping[str, Any],
    batch: Mapping[str, Any],
    protocol: Mapping[str, Any],
    protocol_sha256: str,
    analysis: Mapping[str, Any],
    analysis_result: Mapping[str, Any],
    decision: Mapping[str, Any] | None,
    issued_at: str,
) -> dict[str, Any]:
    """把已决定的评估状态组装为时点固定的护照快照。"""

    return {
        "passport_id": passport_id,
        "passport_version": passport_version,
        "issued_at": issued_at,
        "asset": {
            "asset_id": asset["asset_id"],
            "model_name": asset["model_name"],
            "vendor": asset["vendor"],
        },
        "evidence_revision": {
            "evidence_revision_id": evidence_revision["evidence_revision_id"],
            "version": evidence_revision["version"],
            "content_sha256": evidence_revision["content_sha256"],
        },
        "batch": {"batch_id": batch["batch_id"], "revision": batch["revision"]},
        "protocol": {
            "protocol_id": protocol["protocol_id"],
            "version": protocol["version"],
            "content_sha256": protocol_sha256,
        },
        "analysis": {
            "analysis_id": analysis["analysis_id"],
            "input_sha256": analysis["input_sha256"],
            "algorithm_version": analysis["algorithm_version"],
            "result": analysis_result,
        },
        "decision": None
        if decision is None
        else {
            "decision": decision["decision"],
            "reason": decision["reason"],
            "decided_by": decision["decided_by"],
            "decided_at": decision["decided_at"],
        },
    }


def passport_claims(content: Mapping[str, Any]) -> dict[str, Claim]:
    """从护照快照抽取声明目录对应的全部声明。"""

    result = content["analysis"]["result"]
    protocol_ref = content["protocol"]
    evidence = content["evidence_revision"]
    analysis = content["analysis"]
    provenance = {
        "evidence_revision_id": evidence["evidence_revision_id"],
        "evidence_sha256": evidence["content_sha256"],
        "protocol_id": protocol_ref["protocol_id"],
        "protocol_version": protocol_ref["version"],
        "protocol_sha256": protocol_ref["content_sha256"],
        "analysis_input_sha256": analysis["input_sha256"],
        "algorithm_version": analysis["algorithm_version"],
    }
    claims: dict[str, Claim] = {
        "asset_identity": Claim(
            "asset_identity", CLAIM_CATALOG["asset_identity"], content["asset"], provenance
        ),
        "passport_identity": Claim(
            "passport_identity",
            CLAIM_CATALOG["passport_identity"],
            {
                "passport_id": content["passport_id"],
                "passport_version": content["passport_version"],
                "issued_at": content["issued_at"],
            },
            provenance,
        ),
        "decision": Claim(
            "decision",
            CLAIM_CATALOG["decision"],
            content["decision"],
            provenance,
        ),
        "conclusion": Claim(
            "conclusion",
            CLAIM_CATALOG["conclusion"],
            {"conclusion": result["conclusion"]},
            provenance,
        ),
        "soh_estimate": Claim(
            "soh_estimate",
            CLAIM_CATALOG["soh_estimate"],
            _metric_soh(protocol_ref, result),
            provenance,
        ),
        "rule_results": Claim(
            "rule_results",
            CLAIM_CATALOG["rule_results"],
            {"rules": result["rules"]},
            provenance,
        ),
        "stratum_coverage": Claim(
            "stratum_coverage",
            CLAIM_CATALOG["stratum_coverage"],
            {"strata": {key: value["coverage"] for key, value in result["strata"].items()}},
            provenance,
        ),
        "sample_counts": Claim(
            "sample_counts",
            CLAIM_CATALOG["sample_counts"],
            {
                "included_count": result["included_count"],
                "excluded_count": result["excluded_count"],
            },
            provenance,
        ),
        "evidence_provenance": Claim(
            "evidence_provenance",
            CLAIM_CATALOG["evidence_provenance"],
            provenance,
            provenance,
        ),
    }
    return claims


def _redact(value: Any, field: str) -> Any:
    if isinstance(value, Mapping):
        return {
            key: ("【已隐藏】" if key == field else _redact(item, field))
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact(item, field) for item in value]
    return value


def apply_sensitive_policy(value: Any, hidden_fields: Sequence[str]) -> Any:
    """按策略递归隐藏敏感字段，其余结构与数值原样保留。"""

    result = value
    for field in hidden_fields:
        if field not in SENSITIVE_FIELDS:
            raise ValidationError(f"未知敏感字段: {field}")
        result = _redact(result, field)
    return result


def validate_disposal(
    *,
    audience_type: str,
    audience_id: str,
    purpose: str,
    claim_keys: Sequence[str],
    hidden_fields: Sequence[str],
) -> None:
    if audience_type not in AUDIENCE_TYPES:
        raise ValidationError("audience_type 必须是 insurer、repairer 或 secondary_buyer")
    if not isinstance(audience_id, str) or not audience_id.strip():
        raise ValidationError("audience_id 必须是非空字符串")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValidationError("purpose 必须是非空字符串")
    keys = tuple(claim_keys)
    if not keys:
        raise ValidationError("claim_keys 至少包含一条声明")
    if any(not isinstance(key, str) for key in keys):
        raise ValidationError("claim_keys 必须是字符串数组")
    unknown = sorted(set(keys) - set(CLAIM_CATALOG))
    if unknown:
        raise ValidationError(f"未知声明: {unknown}")
    if len(set(keys)) != len(keys):
        raise ValidationError("claim_keys 不能重复")
    for field in hidden_fields:
        if field not in SENSITIVE_FIELDS:
            raise ValidationError(f"未知敏感字段: {field}")


def build_package_content(
    *,
    passport_content: Mapping[str, Any],
    passport_sha256: str,
    passport_state: str,
    audience_type: str,
    audience_id: str,
    purpose: str,
    claim_keys: Sequence[str],
    hidden_fields: Sequence[str],
    valid_from: str,
    valid_until: str,
    package_id: str,
    created_at: str,
) -> dict[str, Any]:
    """对护照快照做受众投影，生成内容固定的披露包。"""

    all_claims = passport_claims(passport_content)
    statements = []
    for key in claim_keys:
        claim = all_claims[key]
        statements.append({
            "key": claim.key,
            "label": claim.label,
            "value": apply_sensitive_policy(claim.value, hidden_fields),
            "evidence": claim.evidence,
        })
    return {
        "package_id": package_id,
        "created_at": created_at,
        "audience": {"type": audience_type, "id": audience_id.strip()},
        "purpose": purpose.strip(),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "passport": {
            "passport_id": passport_content["passport_id"],
            "passport_version": passport_content["passport_version"],
            "content_sha256": passport_sha256,
            "state": passport_state,
        },
        "redacted_fields": sorted(hidden_fields),
        "statements": statements,
        "note": "本包仅含批准范围内的声明及其原证据摘要，不提供内部记录读取入口。",
    }
