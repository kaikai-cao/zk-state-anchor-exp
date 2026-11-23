# 设计决策与取舍

## 1. 外部 anchor 使用 SHA-256，而不是 Poseidon

D1-E 的 checkpoint、日志与状态根均为 SHA-256。为了避免擅自改变已冻结的 D1-E，本轮把 D2-A 的 Poseidon GR/RR 以规范 32 字节编码放入 SHA-256 锚点。

- 优点：与 D1-E 现有承诺和 Merkle 算法直接兼容；验证器可在电路外实现。
- 代价：本轮**不**在 Halo2 电路内验证 anchor digest；SHA-256 只是外部承诺。
- 未做的事：没有“为了统一 Poseidon”修改 D1-E，也没有实现 SHA-256 电路。

## 2. 三个承诺分离，不互相替代

`state_root`（D1-E 授权历史）、`log_root`（透明日志 Merkle Root）、`anchor_digest`（GR/RR + epoch + policy + 前驱）各自承诺不同对象。验证器只检查它们之间的**可验证关系**：锚点记录以叶子进入日志，日志根进入被 QC 认证的 checkpoint，checkpoint 的 GR/RR 由 Halo2 public inputs 匹配。

不允许把 `state_root` 直接替换成 `log_root`（D1-E R1 已修过同类问题），也不允许仅凭记录在日志中就声称语义状态一致。

## 3. QC 验签覆盖完整 checkpoint 编码

按 D1-E `src/quorum.py:81-98`，QC 验证检查 `checkpoint_hash`、`epoch`、`previous_hash` 和 3 个以上不同见证者对 `encode_checkpoint(cp)` 的 Ed25519 签名。本 adapter 逐字节镜像 `encode_checkpoint`，因此 `log_root`、`state_root`、`policy_version`、`witness_set_root`、`log_size`、`timestamp` 都在签名覆盖范围内。

## 4. 拒绝原因保留为枚举

统一 `false` 会掩盖失败发生在哪一层。验证器返回具体原因（九个任务包要求的码 + 两个细分码 `ANCHOR_EPOCH_MISMATCH`、`ANCHOR_RECORD_MISMATCH`），便于区分：

- 数据绑定错误（digest / public input / policy / predecessor）；
- 日志错误（inclusion）；
- quorum 错误；
- 状态链错误（gap / rollback）；
- freshness 错误。

这不是“为了测试而加码”，而是研究可观测性要求：需要知道组合验证究竟在哪一层失败。

## 5. Freshness 是强制外部假设

验证器**总是**调用 freshness provider。provider 不可用或返回与 presented checkpoint 不一致的旧状态，都返回 `FRESHNESS_UNAVAILABLE`。不存在“QC 有效就接受”的回退路径。

这一设计的意义是：把“状态认证”和“状态最新性”建模为两个独立信任边界。前者由 Merkle + QC 提供，后者由外部 provider 提供。测试 Provider 只是模拟，不构成生产服务。

## 6. 场景构造器单一来源

测试与 `src/bin/evidence.rs` 共用 `src/scenarios.rs`。这样 T01–T20 的断言、报告表格与执行记录都来自同一组构造代码，不会出现“报告写一套、测试跑另一套”。

## 7. 创新边界

本轮结果是**系统集成原型**：把已有的 Merkle inclusion、quorum certificate、规范化编码、本地 epoch 高水位与外部 freshness 接口组合起来，并明确各层的信任边界。没有提出新的密码学原语，也没有证明新的安全属性。如果后续发现某个具体缺口（例如 GR/RR 与 `state_root` 的语义绑定），应围绕该缺口继续研究，而不是把本轮组合包装成创新。
