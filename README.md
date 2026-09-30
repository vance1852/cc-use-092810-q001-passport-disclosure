# 大型储能电池全生命周期协同平台

本项目是一套可离线运行的 Python 服务端平台，服务于大型储能电池从入库、状态评估、组件检测、场站调拨到退役处置的协同管理。平台将资产流转、评估协议、质量决定、幂等结果和审计事件保存在 SQLite 中，供运营、质量、维修和审计人员在单个 Linux 应用容器内使用。

## 目录

- `src/battery_logistics/`：储能场站、调拨走廊、资产批次、容量申请、分配与处置情景；
- `src/battery_assurance/`：电池资产、证据版本、评估协议、观测导入、排除复核、分析任务、准入决定与受众化护照披露；
- `src/component_quality/`：电芯组件批次、响应测量、统计分析、账号权限和质量审批；
- `fixtures/`：离线验收使用的评估协议与结构化观测；
- `tests/`：领域规则、错误边界、事务、权限、HTTP API、受众披露和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m battery_logistics.acceptance --workspace .
PYTHONPATH=src python3 -m battery_assurance.acceptance --workspace .
PYTHONPATH=src python3 -m component_quality.acceptance
```

三条命令会在临时 SQLite 数据库中完成资产调拨、状态评估和组件质量流程，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m battery_logistics.api --database battery-logistics.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m battery_assurance.api --database battery-assurance.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m component_quality.api --database component-quality.sqlite3 --host 127.0.0.1 --port 8082
```

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 受众化电池护照披露

在批次完成分析与准入决定后，资产责任方（`operator` 角色）可以签发电池护照，并面向保险机构、维修承包商、二手受让方等外部受众创建受众化披露包：

- `POST /passports`：基于已决定批次签发不可变护照，内容规范化后计算 SHA-256；
- `POST /disclosures`：选择护照版本、受众类型与标识、使用目的、允许查看的声明（`asset_identity`、`evidence_provenance`、`assessment_summary`、`assessment_rules`、`capacity_metrics`、`decision`）、有效期与脱敏策略（`mask_commercial` 隐藏供应商/合同决定理由，`full` 不额外脱敏），生成版本化、内容固定的披露包，并一次性下发访问凭证；
- `POST /disclosures/read`：接收方凭访问凭证读取固定内容，支持 `X-Grant-Token` 头；
- `POST /disclosures/{package_id}/withdraw`：主动撤回，立即阻止新读取；
- `POST /passports/{passport_id}/revoke`：护照吊销，立即阻止该护照全部披露包的新读取，且不能新建披露；
- `GET /disclosures/{package_id}/verify`：重新计算包与各声明的摘要、核对原始记录锚点；
- `GET /disclosures/ledger` 与 `GET /disclosures/access`：合规人员台账（批准范围、当前状态）与访问报告（谁在何时因何目的看过哪些声明，含被拒绝的尝试）。

关键性质：

1. **内容固定可核验**：信封与每条声明都有规范化 SHA-256；声明仅携带 `record/locator/sha256` 形式的原证据锚点，读取时逐条复核，接收方无法借包内引用读取未授权记录。
2. **同申请幂等、改范围新版本**：由护照内容摘要、受众、目的、声明范围、有效期和脱敏策略组成申请指纹；相同申请重试返回原包（不重发凭证），改变受众或范围则产生新版本。
3. **失效立即生效、留痕不消失**：到期、撤回、吊销实时阻止读取，但已交付的固定摘要与全部访问事实（含拒绝原因）持续留痕。
