# 大型储能电池全生命周期协同平台

本项目是一套可离线运行的 Python 服务端平台，服务于大型储能电池从入库、状态评估、组件检测、场站调拨到退役处置的协同管理。平台将资产流转、评估协议、质量决定、幂等结果和审计事件保存在 SQLite 中，供运营、质量、维修和审计人员在单个 Linux 应用容器内使用。

## 目录

- `src/battery_logistics/`：储能场站、调拨走廊、资产批次、容量申请、分配与处置情景；
- `src/battery_assurance/`：电池资产、证据版本、评估协议、观测导入、排除复核、分析任务、准入决定，以及电池护照与受众化披露包；
- `src/component_quality/`：电芯组件批次、响应测量、统计分析、账号权限和质量审批；
- `fixtures/`：离线验收使用的评估协议与结构化观测；
- `tests/`：领域规则、错误边界、事务、权限、HTTP API 和命令行验收测试。

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

资产责任方（`custodian` 角色）从已形成准入决定的批次签发不可变护照版本，再面向
保险机构（`insurer`）、维修承包商（`repairer`）和二手受让方（`secondary_buyer`）
创建披露包，逐包选择使用目的、允许查看的声明（见 `passports.CLAIM_CATALOG`）、
按策略隐藏的敏感字段（如 `vendor`、`reason`）和有效期限。

- 披露包内容是护照时点快照的确定性投影，整体计算 SHA-256；接收方无需内部权限即可
  离线核验包摘要、护照摘要与证据/协议/分析输入摘要链。包内不含内部记录句柄，
  无法借引用读取未授权记录。
- 同一申请（护照版本、受众、目的、声明范围、敏感策略、有效期均相同）重试返回原包；
  任一要素变化产生新版本。
- 授权到期、责任方主动撤回或护照吊销会立即阻止新的读取（令牌以 SHA-256 哈希存储），
  已交付的包内容与全部访问事实（含拒绝原因）继续在 `disclosure_accesses` 留痕。
- 合规人员（`auditor`）可列出披露、查看访问轨迹，并用
  `GET /disclosures/{id}/verify` 重算投影确认任何披露都未超出批准范围。
