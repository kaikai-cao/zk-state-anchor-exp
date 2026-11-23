# EXP-D2-B-01 — ZkStateAnchor 协议与参考实现

解决 D2-A 的信任缺口：Halo2 能证明授权路径相对于给定 `GR/RR` 成立，但不能单独证明这两个 Root 属于经过 quorum 认证的状态。本仓实现电路外的状态锚定验证器，并运行 T01–T20 场景矩阵。

**本轮不修改 D1-E 或 D2-A，不实现 Halo2 内部 anchor 电路，不做性能优化。**

## 复现

```bash
cargo test --locked -- --nocapture     # 完整测试日志（含正常/回滚执行轨迹）
cargo run --bin evidence               # 生成 results/verification_results.json
python tools/export_report.py          # 生成 results/experiment_report.md
```

## 结构

```
src/
  encoding.rs   确定性编码、FieldBytes/Hash32、SHA-256 域标签
  anchor.rs     AuthzStateAnchor、AnchorRecord、Halo2 public inputs adapter
  log.rs        RFC6962 inclusion proof（非 2 幂树形）
  checkpoint.rs D1-E checkpoint 编码 adapter（逐行核查原仓库）
  quorum.rs     4 见证者 3-of-4 Ed25519 QC adapter
  freshness.rs  FreshnessProvider trait + 三个测试 Provider
  errors.rs     带原因的拒绝枚举
  verifier.rs   九步外部验证器
  scenarios.rs  T01–T20 场景构造器（测试与报告共用）
  bin/evidence.rs 导出逐项结果与执行记录
docs/协议、威胁模型、设计决策
tests/五个测试文件，共 24 个集成测试 + 4 个库单测（含 D1-E 编码跨语言比对）
results/test_log.txt、experiment_report.md、verification_results.json
```

## 三个承诺

| 名称 | 来源 | 对象 |
| --- | --- | --- |
| `state_root` | D1-E | 授权事件历史承诺 |
| `log_root` | D1-E 透明日志 | RFC6962 Merkle Root，包含 AnchorRecord 叶子 |
| `anchor_digest` | D2-B | GR/RR + epoch + policy + 前驱锚点的 SHA-256 外部摘要 |

三者不互相替代。验证器只验证它们之间的可验证关系与 QC 认证；**不证明 GR/RR 与 `state_root` 背后的事件历史语义一致**，该责任仍在授权注册表构建者。

## 边界

- QC 只证明 quorum 认证，不证明最新性；
- 本地 epoch 高水位只防已见过的回滚；冷启动必须依赖外部 freshness；
- provider 不可用或返回旧 checkpoint 一律拒绝；
- 测试 Provider 是模拟，不代表生产级 freshness 服务；
- 不证明 DENY、不在电路内验 SHA-256/Ed25519、不实现 BFT。
