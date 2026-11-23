# EXP-D2-B-01 / R2 — ZkStateAnchor 协议与参考实现

解决 D2-A 的信任缺口：Halo2 能证明授权路径相对于给定 `GR/RR` 成立，但不能单独证明这两个 Root 属于经过 quorum 认证的状态。本仓实现电路外的状态锚定验证器，运行 T01–T20 场景矩阵；R1 修复可信见证者集合绑定与结构化 freshness（W01–W10 / F01–F06），**R2 强制验证 Trusted Witness Set 配置有效性（C01–C12）**。

**不修改 D1-E 或 D2-A，不实现 Halo2 内部 anchor 电路，不做性能优化；R2 不扩展协议、不改 3-of-4 默认实验参数。**

## 复现

```bash
cargo fmt --all -- --check
cargo test --locked -- --nocapture     # 59 项测试，含 W01–W10 / F01–F06 / C01–C12
cargo clippy --locked --all-targets -- -D warnings
cargo run --bin evidence               # 生成 results/verification_results.json
python tools/export_report.py          # 生成 results/experiment_report.md（R1 章节；R2 小节单独增补）
python tests/vectors/generate_witness_vectors.py   # 从 D1-E Python 函数重生成固定向量
```

## 结构

```
src/
  encoding.rs   确定性编码、FieldBytes/Hash32、SHA-256 域标签
  anchor.rs     AuthzStateAnchor、AnchorRecord、Halo2 public inputs adapter
  log.rs        RFC6962 inclusion proof（非 2 幂树形）
  checkpoint.rs D1-E checkpoint 编码 adapter（逐行核查原仓库）
  quorum.rs     测试签名工具 TestQuorumSigner（公开 seed，仅构造测试 QC）
  witness_set.rs 可信见证者集合：带外 expected_root、配置校验、D1-E 语义根、QC 验签（R1/R2）
  freshness.rs  FreshnessProvider trait + 三个测试 Provider
  errors.rs     带原因的拒绝枚举
  verifier.rs   外部验证器（集合绑定 + 结构化 freshness）
  scenarios.rs  T01–T20 场景构造器（测试与报告共用）
  bin/evidence.rs 导出逐项结果与执行记录
docs/协议、威胁模型、设计决策
tests/八个测试文件，共 55 个集成测试 + 4 个库单测；vectors/witness_set_vectors.json 为 D1-E Python 生成的固定向量
results/test_log.txt、clippy_log.txt、experiment_report.md、verification_results.json、r1_results.json、r2_results.json
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
- 验证器只接收带外可信公钥集合，无私钥、无公开 seed 派生路径；公开 seed 派生的 `TestQuorumSigner` 只用于测试；
- 生产配置必须经 `TrustedWitnessSet::from_trusted_config` 显式接收带外 expected_root；空集合、零阈值、阈值大于唯一公钥数、重复 ID、单钥多 ID 在构造期拒绝；
- 验签前强制核对 `computed_root == expected_root == checkpoint.witness_set_root`，重复 witness ID 不重复计票；
- freshness 由 `TrustedCheckpoint` 的 epoch + hash 双字段决定，与日志文本无关；
- 本地 epoch 高水位只防已见过的回滚；冷启动必须依赖外部 freshness；
- provider 不可用或返回旧 checkpoint 一律拒绝；
- 测试 Provider 与测试密钥均为模拟，不代表生产级服务或安全密钥；
- 不证明 DENY、不在电路内验 SHA-256/Ed25519、不实现 BFT。
