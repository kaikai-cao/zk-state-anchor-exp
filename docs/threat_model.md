# 威胁模型与安全属性

## 1. 保护对象

1. Halo2 proof 中 `GR/RR` 与经过 quorum 认证的授权状态之间的绑定；
2. 授权锚点摘要链 `A_{e-1} → A_e` 的前驱关系；
3. 锚点记录在透明日志中的 inclusion 事实；
4. 客户端已经认可的状态不被回滚；
5. 冷启动客户端在没有外部可信信息时不得声称已获得最新状态。

## 2. 参与方与能力

| 参与方 | 被假设的能力 | 在本轮模型中的角色 |
| --- | --- | --- |
| 恶意 prover / gateway | 可篡改 anchor 字段、Halo2 public inputs、checkpoint 字段、伪造 inclusion proof、重放旧 checkpoint | 主要攻击来源 |
| 日志文件 | 可修改/替换已有日志内容或提供另一棵树的 proof | T08/T09/T20 |
| 见证者 | 可被收买以对错误 checkpoint 签名，但假定至少 3 个诚实才能形成 QC | T10/T11；双签锁定由 D1-E 负责 |
| Freshness Provider | 可返回旧 checkpoint，或完全不可用 | T16/T17；本轮为测试模拟 |
| 客户端 | 持有本地最高认可 checkpoint；冷启动时没有 | T14/T15/T16 |

## 3. 属性与对应测试

| 属性 | 本轮是否提供 | 机制 | 测试 |
| --- | --- | --- | --- |
| 锚点摘要自洽 | 是 | `A_e` 重算与 record 内 digest 比对 | T07 |
| Halo2 GR/RR 绑定 | 是（字节级） | public inputs 与 anchor GR/RR 逐字节比对 | T02/T03/T18 |
| epoch/policy 绑定 | 是 | anchor、checkpoint、expected 三方比对 | T04/T05/T13/T19 |
| 日志 inclusion | 是 | RFC 6962 inclusion proof + log_id 约束 | T08/T09/T20 |
| checkpoint 认证 | 是 | D1-E 3-of-4 QC，验签覆盖完整 checkpoint 编码 | T10/T11 |
| checkpoint 连续性 | 是 | previous_hash、epoch 与客户端高水位 | T12/T13/T14 |
| 锚点前驱连续性 | 是 | `prev_anchor_digest` 与可信前驱比对 | T06 |
| 防客户端已知状态回滚 | 是 | 本地 `known_epoch` 单调检查 | T14 |
| 冷启动最新性 | 仅在 provider 假设下 | Freshness Provider 匹配 attestation | T15/T16/T17 |
| QC 蕴含最新性 | **否** | 明确不提供 | 见 §4 |
| GR/RR 与 state_root 语义一致 | **否** | 外部注册表假设 | 见 §4 |
| 双签 / split-view 检测 | **否** | 属于 D1-E 层 | 见 §4 |
| DENY / 不存在性证明 | **否** | 不在 D2-B 范围 | 见 §4 |

## 4. 明确不提供的保证

- QC 不等于最新性。三个诚实见证者签名只认证他们签署的 checkpoint；网络分区下可能存在更新但未被见证者看到的 checkpoint。
- 本地 epoch 高水位只防“已见过”的回滚，不防冷启动拿到旧状态。
- inclusion proof 只证明记录在该 Merkle 树中，不证明树是最新树，也不证明记录语义正确。
- 本轮 `state_root` 与 `log_root` 是 D1-E 的两个不同承诺；`anchor_digest` 是第三个外部承诺。验证器不证明三者语义等价。
- 不验证 Ed25519 签发者身份、不验证授权图 DENY、不在电路内验证 SHA-256、不实现 BFT 共识。

## 5. 安全结论的表述边界

本轮结果应表述为：**参考实现按上述信任假设与测试 Provider 行为通过 20 项场景**。不得表述为：生产环境最新性已解决、密码学创新已成立、或 D1-E/D2-A 已被完整安全审计。
