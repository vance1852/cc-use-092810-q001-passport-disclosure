"""受众化披露用例：护照签发、披露包生成、受控读取与合规留痕。"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import timedelta
from typing import Any, Mapping

from .clock import SystemClock, isoformat
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .passports import (
    build_package_content,
    build_passport_content,
    passport_claims,
    validate_disposal,
)
from .service import ROLE_PERMISSIONS
from .storage import initialize, transaction


class DisclosureService:
    """管理电池护照版本与面向外部机构的固定披露包。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

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
        if permission not in ROLE_PERMISSIONS.get(user["role"], set()):
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

    # -- 护照签发与吊销 -----------------------------------------------------

    def issue_passport(
        self, actor_id: str, passport_id: str, passport_version: int, batch_id: str
    ) -> dict[str, Any]:
        self._require(actor_id, "passport.issue")
        if isinstance(passport_version, bool) or not isinstance(passport_version, int) or passport_version <= 0:
            raise ValidationFailed("passport_version 必须是正整数")
        batch = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if batch is None:
            raise NotFound("批次不存在")
        if batch["state"] != "decided":
            raise InvalidState("只有已形成准入决定的批次才能签发护照")
        decision = self.connection.execute(
            "SELECT * FROM decisions WHERE batch_id=? ORDER BY decision_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        analysis = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?",
            (decision["analysis_id"], batch_id),
        ).fetchone()
        if analysis is None:
            raise NotFound("决定对应的分析版本不存在")
        protocol = self.connection.execute(
            "SELECT * FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (batch["protocol_id"], batch["protocol_version"]),
        ).fetchone()
        evidence = self.connection.execute(
            "SELECT * FROM evidence_revisions WHERE evidence_revision_id=?",
            (batch["evidence_revision_id"],),
        ).fetchone()
        asset = self.connection.execute(
            "SELECT * FROM battery_assets WHERE asset_id=?", (evidence["asset_id"],)
        ).fetchone()
        analysis_result = json.loads(analysis["result_json"])
        issued_at = self._now()
        content = build_passport_content(
            passport_id=passport_id,
            passport_version=passport_version,
            asset=asset,
            evidence_revision=evidence,
            batch=batch,
            protocol=protocol,
            protocol_sha256=protocol["content_sha256"],
            analysis=analysis,
            analysis_result=analysis_result,
            decision=decision,
            issued_at=issued_at,
        )
        text = canonical_json(content)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        revision_id = f"{passport_id}-v{passport_version}"
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO passport_revisions(passport_revision_id,passport_id,asset_id,"
                    "passport_version,batch_id,analysis_id,canonical_json,content_sha256,state,"
                    "issued_by,issued_at) VALUES(?,?,?,?,?,?,?,?, 'issued',?,?)",
                    (
                        revision_id, passport_id, asset["asset_id"], passport_version, batch_id,
                        analysis["analysis_id"], text, digest, actor_id, issued_at,
                    ),
                )
                self._audit(
                    "passport",
                    revision_id,
                    "passport.issued",
                    actor_id,
                    {
                        "passport_id": passport_id,
                        "passport_version": passport_version,
                        "batch_id": batch_id,
                        "content_sha256": digest,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("护照版本编号或内容摘要冲突") from exc
        return {
            "passport_revision_id": revision_id,
            "passport_id": passport_id,
            "passport_version": passport_version,
            "state": "issued",
            "content_sha256": digest,
            "issued_at": issued_at,
        }

    def _passport_row(self, passport_id: str, passport_version: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM passport_revisions WHERE passport_id=? AND passport_version=?",
            (passport_id, passport_version),
        ).fetchone()
        if row is None:
            raise NotFound("护照版本不存在")
        return row

    def revoke_passport(self, actor_id: str, passport_id: str, passport_version: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "passport.revoke")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("吊销原因不能为空")
        passport = self._passport_row(passport_id, passport_version)
        if passport["state"] != "issued":
            raise InvalidState("护照已经吊销")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE passport_revisions SET state='revoked',revoked_by=?,revoked_at=?,revoke_reason=? "
                "WHERE passport_revision_id=? AND state='issued'",
                (actor_id, self._now(), reason.strip(), passport["passport_revision_id"]),
            )
            self.connection.execute(
                "UPDATE disclosure_packages SET state='revoked' "
                "WHERE passport_revision_id=? AND state='active'",
                (passport["passport_revision_id"],),
            )
            self._audit(
                "passport",
                passport["passport_revision_id"],
                "passport.revoked",
                actor_id,
                {"reason": reason.strip()},
            )
        return {"passport_revision_id": passport["passport_revision_id"], "state": "revoked"}

    # -- 披露包生成 ---------------------------------------------------------

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _stored_summary(self, row: sqlite3.Row, token: str | None = None) -> dict[str, Any]:
        summary = {
            "package_id": row["package_id"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "package_sha256": row["package_sha256"],
            "passport_revision_id": row["passport_revision_id"],
            "audience_type": row["audience_type"],
            "audience_id": row["audience_id"],
            "purpose": row["purpose"],
            "claim_keys": json.loads(row["claim_keys_json"]),
            "redacted_fields": json.loads(row["sensitive_policy_json"]),
            "valid_from": row["valid_from"],
            "valid_until": row["valid_until"],
            "state": row["state"],
            "created_at": row["created_at"],
        }
        if token is not None:
            summary["access_token"] = token
        return summary

    def create_disclosure(self, actor_id: str, request: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "disclosure.create")
        passport_id = request.get("passport_id")
        passport_version = request.get("passport_version")
        audience_type = request.get("audience_type")
        audience_id = request.get("audience_id")
        purpose = request.get("purpose")
        claim_keys = request.get("claim_keys", [])
        hidden_fields = request.get("hidden_fields", [])
        validity_seconds = request.get("validity_seconds")
        if isinstance(passport_version, bool) or not isinstance(passport_version, int):
            raise ValidationFailed("passport_version 必须是整数")
        if not isinstance(passport_id, str) or not passport_id.strip():
            raise ValidationFailed("passport_id 必须是非空字符串")
        if isinstance(validity_seconds, bool) or not isinstance(validity_seconds, int) or validity_seconds <= 0:
            raise ValidationFailed("validity_seconds 必须是正整数")
        if not isinstance(claim_keys, (list, tuple)) or not isinstance(hidden_fields, (list, tuple)):
            raise ValidationFailed("claim_keys 与 hidden_fields 必须是数组")
        try:
            validate_disposal(
                audience_type=audience_type,
                audience_id="" if audience_id is None else audience_id,
                purpose="" if purpose is None else purpose,
                claim_keys=claim_keys,
                hidden_fields=hidden_fields,
            )
        except Exception as exc:
            raise ValidationFailed(str(exc)) from exc
        passport = self._passport_row(passport_id, passport_version)
        if passport["state"] != "issued":
            raise InvalidState("护照已吊销，不能创建新的披露")
        fingerprint = content_digest([{
            "passport_revision_id": passport["passport_revision_id"],
            "audience_type": audience_type,
            "audience_id": audience_id.strip(),
            "purpose": purpose.strip(),
            "claim_keys": list(claim_keys),
            "hidden_fields": sorted(hidden_fields),
            "validity_seconds": validity_seconds,
        }])
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT * FROM disclosure_packages WHERE fingerprint_sha256=?", (fingerprint,)
            ).fetchone()
            if existing is not None:
                return self._stored_summary(existing)
            now = self.clock.now()
            valid_from = isoformat(now)
            valid_until = isoformat(now + timedelta(seconds=validity_seconds))
            package_id = f"pkg-{fingerprint[:24]}"
            passport_content = json.loads(passport["canonical_json"])
            package = build_package_content(
                passport_content=passport_content,
                passport_sha256=passport["content_sha256"],
                passport_state="issued",
                audience_type=audience_type,
                audience_id=audience_id,
                purpose=purpose,
                claim_keys=claim_keys,
                hidden_fields=hidden_fields,
                valid_from=valid_from,
                valid_until=valid_until,
                package_id=package_id,
                created_at=valid_from,
            )
            package_text = canonical_json(package)
            package_sha = hashlib.sha256(package_text.encode("utf-8")).hexdigest()
            token = secrets.token_urlsafe(32)
            self.connection.execute(
                "INSERT INTO disclosure_packages(package_id,fingerprint_sha256,passport_revision_id,"
                "audience_type,audience_id,purpose,claim_keys_json,sensitive_policy_json,"
                "valid_from,valid_until,validity_seconds,package_json,package_sha256,token_hash,"
                "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    package_id, fingerprint, passport["passport_revision_id"], audience_type,
                    audience_id.strip(), purpose.strip(), canonical_json(list(claim_keys)),
                    canonical_json(sorted(hidden_fields)), valid_from, valid_until, validity_seconds,
                    package_text, package_sha, self._hash_token(token), actor_id, valid_from,
                ),
            )
            self._audit(
                "disclosure",
                package_id,
                "disclosure.created",
                actor_id,
                {
                    "passport_revision_id": passport["passport_revision_id"],
                    "audience_type": audience_type,
                    "audience_id": audience_id.strip(),
                    "purpose": purpose.strip(),
                    "claim_keys": list(claim_keys),
                    "redacted_fields": sorted(hidden_fields),
                    "valid_until": valid_until,
                    "package_sha256": package_sha,
                },
            )
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        return self._stored_summary(row, token)

    # -- 接收方读取 ---------------------------------------------------------

    def _record_access(
        self, package_id: str, result: str, audience_id: str | None, detail: str
    ) -> None:
        self.connection.execute(
            "INSERT INTO disclosure_accesses(package_id,accessed_at,result,audience_id,detail) "
            "VALUES(?,?,?,?,?)",
            (package_id, self._now(), result, audience_id, detail),
        )

    def read_disclosure(self, token: str, audience_id: str | None = None) -> dict[str, Any]:
        if not isinstance(token, str) or not token:
            raise Forbidden("披露令牌缺失")
        row = self.connection.execute(
            "SELECT p.*, r.passport_id, r.state AS passport_state "
            "FROM disclosure_packages p JOIN passport_revisions r "
            "ON r.passport_revision_id=p.passport_revision_id WHERE p.token_hash=?",
            (self._hash_token(token),),
        ).fetchone()
        if row is None:
            raise Forbidden("披露令牌无效")
        if audience_id is not None and audience_id.strip() != row["audience_id"]:
            with transaction(self.connection, immediate=True):
                self._record_access(row["package_id"], "denied_token", audience_id, "受众身份不匹配")
            raise Forbidden("披露令牌与受众不匹配")
        now = self._now()
        if row["passport_state"] == "revoked" or row["state"] == "revoked":
            with transaction(self.connection, immediate=True):
                self._record_access(row["package_id"], "denied_revoked", row["audience_id"], "护照已吊销")
            raise Forbidden("护照已吊销，披露不可读取")
        if row["state"] == "withdrawn":
            with transaction(self.connection, immediate=True):
                self._record_access(row["package_id"], "denied_withdrawn", row["audience_id"], "披露已撤回")
            raise Forbidden("披露已被资产责任方撤回")
        if now >= row["valid_until"]:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "UPDATE disclosure_packages SET state='expired' WHERE package_id=? AND state='active'",
                    (row["package_id"],),
                )
                self._record_access(row["package_id"], "denied_expired", row["audience_id"], "授权已到期")
            raise Forbidden("披露授权已到期")
        with transaction(self.connection, immediate=True):
            self._record_access(row["package_id"], "delivered", row["audience_id"], None)
        return {
            "status": "delivered",
            "state": row["state"],
            "package": json.loads(row["package_json"]),
            "package_sha256": row["package_sha256"],
            "valid_until": row["valid_until"],
        }

    def withdraw_disclosure(self, actor_id: str, package_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "disclosure.withdraw")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("撤回原因不能为空")
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound("披露包不存在")
        if row["state"] != "active":
            raise InvalidState(f"披露包当前状态为 {row['state']}，不能撤回")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE disclosure_packages SET state='withdrawn',withdrawn_at=?,withdraw_reason=? "
                "WHERE package_id=? AND state='active'",
                (self._now(), reason.strip(), package_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("披露包状态已变化")
            self._audit(
                "disclosure",
                package_id,
                "disclosure.withdrawn",
                actor_id,
                {"reason": reason.strip(), "audience_id": row["audience_id"]},
            )
        return {"package_id": package_id, "state": "withdrawn"}

    # -- 合规视图 -----------------------------------------------------------

    def list_disclosures(self, actor_id: str, passport_id: str | None = None) -> list[dict[str, Any]]:
        self._require(actor_id, "disclosure.read")
        sql = (
            "SELECT p.* FROM disclosure_packages p "
            "JOIN passport_revisions r ON r.passport_revision_id=p.passport_revision_id"
        )
        params: list[Any] = []
        if passport_id is not None:
            sql += " WHERE r.passport_id=?"
            params.append(passport_id)
        sql += " ORDER BY p.rowid"
        rows = self.connection.execute(sql, params).fetchall()
        return [self._stored_summary(row) for row in rows]

    def disclosure_trail(self, actor_id: str, package_id: str) -> dict[str, Any]:
        self._require(actor_id, "disclosure.read")
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound("披露包不存在")
        accesses = self.connection.execute(
            "SELECT accessed_at,result,audience_id,detail FROM disclosure_accesses "
            "WHERE package_id=? ORDER BY access_id",
            (package_id,),
        ).fetchall()
        return {
            "package": self._stored_summary(row),
            "accesses": [dict(item) for item in accesses],
        }

    def verify_disclosure_scope(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """重算投影并比对冻结包，确认披露未超出批准范围且内容未被篡改。"""

        self._require(actor_id, "disclosure.read")
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound("披露包不存在")
        passport = self.connection.execute(
            "SELECT * FROM passport_revisions WHERE passport_revision_id=?",
            (row["passport_revision_id"],),
        ).fetchone()
        checks: dict[str, bool] = {}
        stored_package = json.loads(row["package_json"])
        claim_keys = json.loads(row["claim_keys_json"])
        hidden_fields = json.loads(row["sensitive_policy_json"])

        recomputed = build_package_content(
            passport_content=json.loads(passport["canonical_json"]),
            passport_sha256=passport["content_sha256"],
            passport_state=passport["state"],
            audience_type=row["audience_type"],
            audience_id=row["audience_id"],
            purpose=row["purpose"],
            claim_keys=claim_keys,
            hidden_fields=hidden_fields,
            valid_from=row["valid_from"],
            valid_until=row["valid_until"],
            package_id=row["package_id"],
            created_at=row["created_at"],
        )
        checks["projection_matches_frozen_package"] = recomputed == stored_package
        checks["package_digest_matches"] = (
            hashlib.sha256(canonical_json(stored_package).encode("utf-8")).hexdigest()
            == row["package_sha256"]
        )
        stored_statements = stored_package.get("statements")
        stored_keys = (
            [item["key"] for item in stored_statements]
            if isinstance(stored_statements, list)
            and all(isinstance(item, dict) and "key" in item for item in stored_statements)
            else None
        )
        checks["statement_keys_equal_approval"] = stored_keys == list(claim_keys)
        checks["statements_within_catalog"] = (
            stored_keys is not None
            and set(stored_keys) <= set(passport_claims(json.loads(passport["canonical_json"])))
        )
        stored_passport = stored_package.get("passport", {})
        checks["passport_digest_unchanged"] = (
            isinstance(stored_passport, dict)
            and stored_passport.get("content_sha256") == passport["content_sha256"]
        )
        return {
            "package_id": package_id,
            "within_scope": all(checks.values()),
            "checks": checks,
            "approved_claim_keys": claim_keys,
            "redacted_fields": hidden_fields,
        }
