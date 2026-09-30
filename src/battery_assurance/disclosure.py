"""受众化电池护照披露。

资产责任方面向保险机构、维修承包商、二手受让方等外部受众签发内容固定的
披露包。包内每条声明只携带按策略脱敏后的可见内容，并保留对原始证据记录
（定位符 + 内容摘要）的可验证关联；接收方凭一次性交付的访问凭证读取，
凭证哈希落库。授权到期、主动撤回或护照吊销立即阻止新的读取，全部访问事实
（含被拒绝的读取）持续留痕。
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime
from typing import Any, Mapping

from .clock import SystemClock, isoformat
from .errors import Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import transaction


AUDIENCE_TYPES = frozenset({"insurer", "repair_contractor", "secondary_buyer", "other"})

REDACTION_POLICIES = frozenset({"mask_commercial", "full"})

DISCLOSURE_PERMISSIONS: Mapping[str, frozenset[str]] = {
    "operator": frozenset({"passport.issue", "passport.revoke", "disclosure.create", "disclosure.withdraw"}),
    "statistician": frozenset(),
    "approver": frozenset(),
    "auditor": frozenset({"disclosure.audit"}),
}

# 声明目录：key -> (来源记录类型, mask_commercial 策略下隐藏的字段)
STATEMENT_CATALOG: Mapping[str, tuple[str, frozenset[str]]] = {
    "asset_identity": ("battery_assets", frozenset({"vendor"})),
    "evidence_provenance": ("evidence_revisions", frozenset()),
    "assessment_summary": ("analyses", frozenset()),
    "assessment_rules": ("analyses", frozenset()),
    "capacity_metrics": ("analyses", frozenset()),
    "decision": ("decisions", frozenset({"reason"})),
}


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 必须是 ISO-8601 时间字符串")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationFailed(f"{field} 不是有效时间") from exc
    if parsed.tzinfo is None:
        raise ValidationFailed(f"{field} 必须带时区")
    return parsed.astimezone()


def _redact(value: Any, hidden: frozenset[str]) -> Any:
    if not hidden:
        return value
    if isinstance(value, Mapping):
        return {key: ("***REDACTED***" if key in hidden else _redact(item, hidden)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, hidden) for item in value]
    return value


class DisclosureService:
    """在与业务服务共享的 SQLite 连接上提供护照签发与受众化披露用例。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in DISCLOSURE_PERMISSIONS.get(user["role"], frozenset()):
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    # ------------------------------------------------------------------ 护照

    def issue_passport(
        self, actor_id: str, passport_id: str, passport_version: str, batch_id: str
    ) -> dict[str, Any]:
        self._require(actor_id, "passport.issue")
        batch = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if batch is None:
            raise NotFound("批次不存在")
        if batch["state"] != "decided":
            raise InvalidState("只有已形成准入决定的批次可以签发护照")
        evidence = self.connection.execute(
            "SELECT * FROM evidence_revisions WHERE evidence_revision_id=?",
            (batch["evidence_revision_id"],),
        ).fetchone()
        protocol = self.connection.execute(
            "SELECT content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (batch["protocol_id"], batch["protocol_version"]),
        ).fetchone()
        decision = self.connection.execute(
            "SELECT * FROM decisions WHERE batch_id=? ORDER BY decision_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        analysis = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=?", (decision["analysis_id"],)
        ).fetchone()
        asset = self.connection.execute(
            "SELECT * FROM battery_assets WHERE asset_id=?", (evidence["asset_id"],)
        ).fetchone()
        result = json.loads(analysis["result_json"])
        issued_at = self._now()
        content = {
            "passport_id": passport_id,
            "passport_version": passport_version,
            "asset_id": asset["asset_id"],
            "issued_at": issued_at,
            "batch": {
                "batch_id": batch["batch_id"],
                "state": batch["state"],
                "sealed_at": batch["sealed_at"],
                "evidence_revision_id": evidence["evidence_revision_id"],
                "evidence_version": evidence["version"],
            },
            "protocol": {
                "protocol_id": batch["protocol_id"],
                "version": batch["protocol_version"],
                "sha256": protocol["content_sha256"],
            },
            "analysis": {
                "analysis_id": analysis["analysis_id"],
                "input_sha256": analysis["input_sha256"],
                "algorithm_version": analysis["algorithm_version"],
                "result": result,
            },
            "decision": {
                "decision_id": decision["decision_id"],
                "decision": decision["decision"],
                "reason": decision["reason"],
                "decided_at": decision["decided_at"],
            },
        }
        text = canonical_json(content)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO passports(passport_id,asset_id,passport_version,batch_id,analysis_id,decision_id,"
                    "canonical_json,content_sha256,issued_by,issued_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        passport_id, asset["asset_id"], passport_version, batch_id,
                        analysis["analysis_id"], decision["decision_id"],
                        text, digest, actor_id, issued_at,
                    ),
                )
                self._audit("passport", passport_id, "passport.issued", actor_id, {
                    "asset_id": asset["asset_id"], "passport_version": passport_version,
                    "batch_id": batch_id, "sha256": digest,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("护照编号、版本或内容冲突") from exc
        return {"passport_id": passport_id, "passport_version": passport_version, "sha256": digest}

    def revoke_passport(self, actor_id: str, passport_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "passport.revoke")
        if not reason.strip():
            raise ValidationFailed("吊销原因不能为空")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT revoked_at FROM passports WHERE passport_id=?", (passport_id,)
            ).fetchone()
            if row is None:
                raise NotFound("护照不存在")
            if row["revoked_at"] is not None:
                raise InvalidState("护照已经吊销")
            self.connection.execute(
                "UPDATE passports SET revoked_by=?,revoked_at=?,revoke_reason=? WHERE passport_id=?",
                (actor_id, self._now(), reason, passport_id),
            )
            self._audit("passport", passport_id, "passport.revoked", actor_id, {"reason": reason})
        return {"passport_id": passport_id, "status": "revoked"}

    # ------------------------------------------------------------- 声明投影

    def _statement_value(self, content: Mapping[str, Any], key: str) -> Any:
        result = content["analysis"]["result"]
        if key == "asset_identity":
            asset = self.connection.execute(
                "SELECT model_name,vendor FROM battery_assets WHERE asset_id=?", (content["asset_id"],)
            ).fetchone()
            return {
                "asset_id": content["asset_id"],
                "model_name": asset["model_name"],
                "vendor": asset["vendor"],
            }
        if key == "evidence_provenance":
            evidence_sha = self.connection.execute(
                "SELECT content_sha256 FROM evidence_revisions WHERE evidence_revision_id=?",
                (content["batch"]["evidence_revision_id"],),
            ).fetchone()["content_sha256"]
            return {
                "evidence_revision_id": content["batch"]["evidence_revision_id"],
                "evidence_version": content["batch"]["evidence_version"],
                "evidence_sha256": evidence_sha,
                "protocol_id": content["protocol"]["protocol_id"],
                "protocol_version": content["protocol"]["version"],
                "protocol_sha256": content["protocol"]["sha256"],
            }
        if key == "assessment_summary":
            return {
                "conclusion": result["conclusion"],
                "included_count": result["included_count"],
                "excluded_count": result["excluded_count"],
            }
        if key == "assessment_rules":
            return result["rules"]
        if key == "capacity_metrics":
            return result["aggregate"]
        if key == "decision":
            return {
                "decision": content["decision"]["decision"],
                "reason": content["decision"]["reason"],
                "decided_at": content["decision"]["decided_at"],
            }
        raise ValidationFailed(f"未知声明: {key}")

    def _source_anchor(self, content: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        """返回声明对应原始记录的定位符与内容摘要（不含任何可读业务字段）。"""

        analysis_id = content["analysis"]["analysis_id"]
        if key == "asset_identity":
            row = self.connection.execute(
                "SELECT asset_id,model_name,vendor,created_at FROM battery_assets WHERE asset_id=?",
                (content["asset_id"],),
            ).fetchone()
            return {
                "record": "battery_assets",
                "locator": f"battery_assets/{row['asset_id']}",
                "sha256": content_digest([dict(row)]),
            }
        if key == "evidence_provenance":
            evidence_id = content["batch"]["evidence_revision_id"]
            digest = self.connection.execute(
                "SELECT content_sha256 FROM evidence_revisions WHERE evidence_revision_id=?", (evidence_id,)
            ).fetchone()["content_sha256"]
            return {"record": "evidence_revisions", "locator": f"evidence_revisions/{evidence_id}", "sha256": digest}
        if key in {"assessment_summary", "assessment_rules", "capacity_metrics"}:
            row = self.connection.execute(
                "SELECT result_json FROM analyses WHERE analysis_id=?", (analysis_id,)
            ).fetchone()
            digest = hashlib.sha256(row["result_json"].encode("utf-8")).hexdigest()
            return {"record": "analyses", "locator": f"analyses/{analysis_id}#result", "sha256": digest}
        if key == "decision":
            decision_id = content["decision"]["decision_id"]
            row = self.connection.execute(
                "SELECT decision_id,batch_id,analysis_id,decision,reason,decided_by,decided_at "
                "FROM decisions WHERE decision_id=?", (decision_id,)
            ).fetchone()
            return {
                "record": "decisions",
                "locator": f"decisions/{decision_id}",
                "sha256": content_digest([dict(row)]),
            }
        raise ValidationFailed(f"未知声明: {key}")

    # ------------------------------------------------------------- 披露申请

    def create_disclosure(
        self,
        actor_id: str,
        passport_id: str,
        audience_type: str,
        audience_ref: str,
        purpose: str,
        statement_keys: list[str],
        valid_from: str,
        valid_until: str,
        redaction_policy: str = "mask_commercial",
    ) -> dict[str, Any]:
        self._require(actor_id, "disclosure.create")
        passport = self.connection.execute(
            "SELECT * FROM passports WHERE passport_id=?", (passport_id,)
        ).fetchone()
        if passport is None:
            raise NotFound("护照不存在")
        if audience_type not in AUDIENCE_TYPES:
            raise ValidationFailed(f"受众类型必须是 {sorted(AUDIENCE_TYPES)} 之一")
        audience_ref = audience_ref.strip()
        purpose = purpose.strip()
        if not audience_ref:
            raise ValidationFailed("受众标识不能为空")
        if not purpose:
            raise ValidationFailed("使用目的不能为空")
        if redaction_policy not in REDACTION_POLICIES:
            raise ValidationFailed(f"脱敏策略必须是 {sorted(REDACTION_POLICIES)} 之一")
        if not isinstance(statement_keys, list) or not statement_keys:
            raise ValidationFailed("至少选择一条允许查看的声明")
        keys = sorted({key.strip() for key in statement_keys if isinstance(key, str) and key.strip()})
        if len(keys) != len(statement_keys):
            raise ValidationFailed("声明列表存在重复或空值")
        unknown = sorted(set(keys) - set(STATEMENT_CATALOG))
        if unknown:
            raise ValidationFailed(f"声明未在目录中定义: {unknown}")
        start = _parse_timestamp(valid_from, "valid_from")
        end = _parse_timestamp(valid_until, "valid_until")
        if start >= end:
            raise ValidationFailed("valid_until 必须晚于 valid_from")
        if end <= self.clock.now().astimezone():
            raise ValidationFailed("有效期截止时间必须晚于当前时间")

        start_text = isoformat(start.astimezone())
        end_text = isoformat(end.astimezone())
        request_payload = [
            passport_id, passport["content_sha256"], audience_type, audience_ref, purpose,
            keys, redaction_policy, start_text, end_text,
        ]
        request_digest = content_digest(request_payload)

        existing = self.connection.execute(
            "SELECT p.package_id FROM disclosure_requests r "
            "JOIN disclosure_packages p ON p.request_id=r.request_id WHERE r.request_sha256=?",
            (request_digest,),
        ).fetchone()
        if existing is not None:
            # 同一申请重试：即便护照此后被吊销，也返回原包（状态反映失效），
            # 不重新交付访问凭证，也不生成新版本。
            return self._package_metadata(existing["package_id"], replayed=True)
        if passport["revoked_at"] is not None:
            raise InvalidState("护照已吊销，不能创建新披露")

        content = json.loads(passport["canonical_json"])
        claims: list[dict[str, Any]] = []
        claim_rows: list[tuple[str, str, str, str, str, str, str]] = []
        for key in keys:
            hidden = STATEMENT_CATALOG[key][1] if redaction_policy == "mask_commercial" else frozenset()
            raw_value = self._statement_value(content, key)
            visible = _redact(raw_value, hidden)
            source = dict(self._source_anchor(content, key))
            top_level_hidden = hidden & (set(raw_value) if isinstance(raw_value, Mapping) else set())
            redacted = sorted(top_level_hidden)
            claim = {
                "statement_key": key,
                "visible": visible,
                "source": source,
                "redacted_fields": redacted,
            }
            claim_digest = content_digest([claim])
            claims.append({**claim, "claim_sha256": claim_digest})
            claim_rows.append((
                key, canonical_json(visible), canonical_json(claim),
                source["record"], source["sha256"], canonical_json(redacted), claim_digest,
            ))

        package_id = "pkg-" + secrets.token_hex(12)
        try:
            with transaction(self.connection, immediate=True):
                # 事务内复查，拦截并发的相同申请。
                racing = self.connection.execute(
                    "SELECT p.package_id FROM disclosure_requests r "
                    "JOIN disclosure_packages p ON p.request_id=r.request_id WHERE r.request_sha256=?",
                    (request_digest,),
                ).fetchone()
                if racing is not None:
                    return self._package_metadata(racing["package_id"], replayed=True)
                if self.connection.execute(
                    "SELECT revoked_at FROM passports WHERE passport_id=?", (passport_id,)
                ).fetchone()["revoked_at"] is not None:
                    raise InvalidState("护照已吊销，不能创建新披露")
                next_version = self.connection.execute(
                "SELECT COALESCE(MAX(package_version), 0) + 1 FROM disclosure_packages WHERE passport_id=?",
                (passport_id,),
            ).fetchone()[0]
            issued_at = self._now()
            envelope = {
                "package_id": package_id,
                "package_version": next_version,
                "passport": {
                    "passport_id": passport_id,
                    "passport_version": passport["passport_version"],
                    "asset_id": passport["asset_id"],
                    "sha256": passport["content_sha256"],
                },
                "audience": {"type": audience_type, "ref": audience_ref},
                "purpose": purpose,
                "valid_from": start_text,
                "valid_until": end_text,
                "issued_at": issued_at,
                "redaction_policy": redaction_policy,
                "statements": claims,
            }
            envelope_text = canonical_json(envelope)
            package_digest = hashlib.sha256(envelope_text.encode("utf-8")).hexdigest()
            request_id = "req-" + secrets.token_hex(8)
            self.connection.execute(
                "INSERT INTO disclosure_requests(request_id,request_sha256,passport_id,audience_type,"
                "audience_ref,purpose,statement_keys_json,redaction_policy,valid_from,valid_until,"
                "requested_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id, request_digest, passport_id, audience_type, audience_ref, purpose,
                    canonical_json(keys), redaction_policy, start_text, end_text, actor_id, issued_at,
                ),
            )
            self.connection.execute(
                "INSERT INTO disclosure_packages(package_id,request_id,passport_id,package_version,"
                "audience_type,audience_ref,purpose,statement_keys_json,redaction_policy,valid_from,"
                "valid_until,envelope_json,content_sha256,issued_by,issued_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    package_id, request_id, passport_id, next_version, audience_type, audience_ref, purpose,
                    canonical_json(keys), redaction_policy, start_text, end_text,
                    envelope_text, package_digest, actor_id, issued_at,
                ),
            )
            for row in claim_rows:
                self.connection.execute(
                    "INSERT INTO package_statements(package_id,statement_key,visible_json,claim_json,"
                    "source_record,source_content_sha256,redacted_fields_json,claim_sha256) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (package_id, *row),
                )
            grant_token = secrets.token_hex(32)
            self.connection.execute(
                "INSERT INTO disclosure_grants(grant_token_hash,package_id,audience_type,audience_ref,"
                "purpose,issued_at) VALUES(?,?,?,?,?,?)",
                (
                    hashlib.sha256(grant_token.encode("utf-8")).hexdigest(),
                    package_id, audience_type, audience_ref, purpose, issued_at,
                ),
            )
            self._audit("disclosure_package", package_id, "disclosure.created", actor_id, {
                "passport_id": passport_id, "package_version": next_version,
                "audience_type": audience_type, "audience_ref": audience_ref,
                "purpose": purpose, "statement_keys": keys,
                "redaction_policy": redaction_policy,
                "valid_from": start_text, "valid_until": end_text,
                "sha256": package_digest,
            })
        except sqlite3.IntegrityError as exc:
            existing = self.connection.execute(
                "SELECT p.package_id FROM disclosure_requests r "
                "JOIN disclosure_packages p ON p.request_id=r.request_id WHERE r.request_sha256=?",
                (request_digest,),
            ).fetchone()
            if existing is not None:
                return self._package_metadata(existing["package_id"], replayed=True)
            raise Conflict("披露包落库冲突") from exc
        response = self._package_metadata(package_id, replayed=False)
        response["grant_token"] = grant_token
        return response

    def _effective_status(self, row: sqlite3.Row, passport_revoked: bool, now: datetime) -> str:
        if passport_revoked:
            return "passport_revoked"
        if row["status"] == "withdrawn":
            return "withdrawn"
        if _parse_timestamp(row["valid_until"], "valid_until") < now:
            return "expired"
        return "active"

    def _package_metadata(self, package_id: str, *, replayed: bool) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound("披露包不存在")
        passport_revoked = self.connection.execute(
            "SELECT revoked_at FROM passports WHERE passport_id=?", (row["passport_id"],)
        ).fetchone()["revoked_at"] is not None
        return {
            "package_id": package_id,
            "package_version": row["package_version"],
            "passport_id": row["passport_id"],
            "audience": {"type": row["audience_type"], "ref": row["audience_ref"]},
            "purpose": row["purpose"],
            "statement_keys": json.loads(row["statement_keys_json"]),
            "redaction_policy": row["redaction_policy"],
            "valid_from": row["valid_from"],
            "valid_until": row["valid_until"],
            "content_sha256": row["content_sha256"],
            "status": row["status"],
            "effective_status": self._effective_status(row, passport_revoked, self.clock.now().astimezone()),
            "replayed": replayed,
            "grant_token": None,
        }

    def withdraw_package(self, actor_id: str, package_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "disclosure.withdraw")
        if not reason.strip():
            raise ValidationFailed("撤回原因不能为空")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT status FROM disclosure_packages WHERE package_id=?", (package_id,)
            ).fetchone()
            if row is None:
                raise NotFound("披露包不存在")
            if row["status"] != "active":
                raise InvalidState("披露包不是有效状态")
            self.connection.execute(
                "UPDATE disclosure_packages SET status='withdrawn',withdrawn_at=?,withdrawn_by=?,"
                "withdraw_reason=? WHERE package_id=?",
                (self._now(), actor_id, reason, package_id),
            )
            self._audit("disclosure_package", package_id, "disclosure.withdrawn", actor_id, {"reason": reason})
        return {"package_id": package_id, "status": "withdrawn"}

    # ------------------------------------------------------------- 接收方读取

    def _log_access(
        self,
        result: str,
        *,
        package_id: str | None,
        package_version: int | None,
        audience_ref: str,
        purpose: str,
        denial_reason: str | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO disclosure_access_log(package_id,package_version,audience_ref,purpose,result,"
            "denial_reason,accessed_at) VALUES(?,?,?,?,?,?,?)",
            (package_id, package_version, audience_ref, purpose, result, denial_reason, self._now()),
        )

    def read_disclosure(self, grant_token: str, audience_ref: str | None = None) -> dict[str, Any]:
        """接收方凭交付时获得的访问凭证读取固定披露内容。"""

        if not isinstance(grant_token, str) or not grant_token.strip():
            raise ValidationFailed("缺少访问凭证")
        token_hash = hashlib.sha256(grant_token.strip().encode("utf-8")).hexdigest()
        grant = self.connection.execute(
            "SELECT * FROM disclosure_grants WHERE grant_token_hash=?", (token_hash,)
        ).fetchone()
        if grant is None:
            # 凭证猜测同样留痕，凭证本身不入库、不落日志。
            with transaction(self.connection, immediate=True):
                self._log_access(
                    "denied_unknown_token", package_id=None, package_version=None,
                    audience_ref=(audience_ref or "unknown").strip(), purpose="",
                    denial_reason="访问凭证不存在",
                )
            raise NotFound("访问凭证无效")
        if audience_ref and audience_ref.strip() != grant["audience_ref"]:
            raise Forbidden("凭证与接收方标识不匹配")
        package = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (grant["package_id"],)
        ).fetchone()
        passport = self.connection.execute(
            "SELECT revoked_at FROM passports WHERE passport_id=?", (package["passport_id"],)
        ).fetchone()
        now = self.clock.now().astimezone()
        blocked: tuple[str, str] | None = None
        if passport["revoked_at"] is not None:
            blocked = ("denied_revoked", "护照已吊销")
        elif package["status"] == "withdrawn":
            blocked = ("denied_withdrawn", "披露包已被资产责任方撤回")
        elif _parse_timestamp(package["valid_until"], "valid_until") < now:
            blocked = ("denied_expired", "披露授权已到期")
        elif _parse_timestamp(package["valid_from"], "valid_from") > now:
            blocked = ("denied_not_yet_valid", "披露授权尚未生效")

        envelope: dict[str, Any] | None = None
        with transaction(self.connection, immediate=True):
            if blocked is not None:
                self._log_access(
                    blocked[0], package_id=package["package_id"], package_version=package["package_version"],
                    audience_ref=grant["audience_ref"], purpose=grant["purpose"], denial_reason=blocked[1],
                )
            else:
                statement_rows = self.connection.execute(
                    "SELECT statement_key,claim_json,claim_sha256 FROM package_statements "
                    "WHERE package_id=? ORDER BY statement_key", (package["package_id"],)
                ).fetchall()
                envelope = json.loads(package["envelope_json"])
                for row in statement_rows:
                    claim = json.loads(row["claim_json"])
                    if content_digest([claim]) != row["claim_sha256"]:
                        # 完整性被破坏：不放内容，访问事实照常提交后再拒绝。
                        self._log_access(
                            "denied_tampered", package_id=package["package_id"],
                            package_version=package["package_version"], audience_ref=grant["audience_ref"],
                            purpose=grant["purpose"], denial_reason="披露包完整性校验失败",
                        )
                        blocked = ("denied_tampered", "披露包完整性校验失败")
                        envelope = None
                        break
                if blocked is None:
                    self.connection.execute(
                        "UPDATE disclosure_grants SET last_offered_at=? WHERE grant_token_hash=?",
                        (self._now(), token_hash),
                    )
                    self._log_access(
                        "served", package_id=package["package_id"], package_version=package["package_version"],
                        audience_ref=grant["audience_ref"], purpose=grant["purpose"],
                    )
        if blocked is not None:
            raise Forbidden(blocked[1])
        return {
            "envelope": envelope,
            "verification": {
                "package_sha256": package["content_sha256"],
                "passport_sha256": envelope["passport"]["sha256"],
                "statement_count": len(envelope["statements"]),
            },
        }

    # ------------------------------------------------------------- 合规留痕

    def verify_package(self, actor_id: str, package_id: str) -> dict[str, Any]:
        self._user(actor_id)
        package = self.connection.execute(
            "SELECT envelope_json,content_sha256,passport_id FROM disclosure_packages WHERE package_id=?",
            (package_id,),
        ).fetchone()
        if package is None:
            raise NotFound("披露包不存在")
        envelope = json.loads(package["envelope_json"])
        recomputed = hashlib.sha256(canonical_json(envelope).encode("utf-8")).hexdigest()
        passport = self.connection.execute(
            "SELECT canonical_json FROM passports WHERE passport_id=?", (package["passport_id"],)
        ).fetchone()
        passport_content = json.loads(passport["canonical_json"])
        rows = self.connection.execute(
            "SELECT statement_key,claim_json,claim_sha256,source_content_sha256 FROM package_statements "
            "WHERE package_id=? ORDER BY statement_key", (package_id,)
        ).fetchall()
        claims = []
        for row in rows:
            claim = json.loads(row["claim_json"])
            live_anchor = self._source_anchor(passport_content, row["statement_key"])
            claims.append({
                "statement_key": row["statement_key"],
                "claim_sha256_ok": content_digest([claim]) == row["claim_sha256"],
                "source_anchor_ok": claim["source"]["sha256"] == row["source_content_sha256"],
                "source_record_live_ok": live_anchor["sha256"] == row["source_content_sha256"],
            })
        return {
            "package_id": package_id,
            "package_sha256": package["content_sha256"],
            "envelope_intact": recomputed == package["content_sha256"],
            "claims": claims,
        }

    def disclosure_ledger(self, actor_id: str, audience_ref: str | None = None) -> list[dict[str, Any]]:
        """合规台账：每个披露包的批准受众、目的、声明范围、有效期与当前状态。"""

        self._require(actor_id, "disclosure.audit")
        sql = (
            "SELECT p.*, pas.revoked_at AS passport_revoked_at FROM disclosure_packages p "
            "JOIN passports pas ON pas.passport_id=p.passport_id"
        )
        params: tuple[Any, ...] = ()
        if audience_ref:
            sql += " WHERE p.audience_ref=?"
            params = (audience_ref.strip(),)
        sql += " ORDER BY p.issued_at, p.package_id"
        now = self.clock.now().astimezone()
        ledger = []
        for row in self.connection.execute(sql, params).fetchall():
            ledger.append({
                "package_id": row["package_id"],
                "package_version": row["package_version"],
                "passport_id": row["passport_id"],
                "audience": {"type": row["audience_type"], "ref": row["audience_ref"]},
                "purpose": row["purpose"],
                "statement_keys": json.loads(row["statement_keys_json"]),
                "redaction_policy": row["redaction_policy"],
                "valid_from": row["valid_from"],
                "valid_until": row["valid_until"],
                "issued_by": row["issued_by"],
                "issued_at": row["issued_at"],
                "content_sha256": row["content_sha256"],
                "effective_status": self._effective_status(row, row["passport_revoked_at"] is not None, now),
            })
        return ledger

    def access_report(self, actor_id: str, package_id: str | None = None) -> list[dict[str, Any]]:
        """回答谁在何时因何目的看过哪些声明（含被拒绝的读取尝试）。"""

        self._require(actor_id, "disclosure.audit")
        sql = (
            "SELECT a.package_id,a.package_version,a.audience_ref,a.purpose,a.result,a.denial_reason,"
            "a.accessed_at,p.statement_keys_json "
            "FROM disclosure_access_log a LEFT JOIN disclosure_packages p ON p.package_id=a.package_id"
        )
        params: tuple[Any, ...] = ()
        if package_id:
            sql += " WHERE a.package_id=?"
            params = (package_id,)
        sql += " ORDER BY a.access_id"
        report = []
        for row in self.connection.execute(sql, params).fetchall():
            report.append({
                "package_id": row["package_id"],
                "package_version": row["package_version"],
                "audience_ref": row["audience_ref"],
                "purpose": row["purpose"],
                "statement_keys": [] if row["statement_keys_json"] is None
                else json.loads(row["statement_keys_json"]),
                "result": row["result"],
                "denial_reason": row["denial_reason"],
                "accessed_at": row["accessed_at"],
            })
        return report
