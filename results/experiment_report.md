# EXP-D2-B-01 实验报告

ZkStateAnchor：协议设计、规范化编码、参考实现与攻击测试

> 性质：**设计 + 工程验证**。本轮不修改 D1-E/D2-A，不实现 Halo2 内部 anchor 电路，不做性能优化。
> 20 项场景的断言、报告表格与执行记录来自同一套 `src/scenarios.rs` 构造器。

## 1. 仓库与提交

- 本地：`D:\Research\zk-state-anchor-exp`
- GitHub：`kaikai-cao/zk-state-anchor-exp`
- 最终 commit SHA：见本次交付汇报与仓库 `main` HEAD（本报告在提交前生成，故不自嵌入 SHA）。

## 2. 完整协议数据结构与规范化编码

`AuthzStateAnchor`：`version:u32`、`epoch:u64`、`policy_version:u32`、`grant_root:FieldBytes`、`revoke_root:FieldBytes`、`prev_anchor_digest:Hash32`、`anchor_digest:Hash32`。

`FieldBytes` 为 Pallas 标量域元素的规范 32 字节大端编码，严格小于模数 `0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`；`Hash32` 为 SHA-256 输出。

编码规则：全部整数大端定长（u32/u64，D1-E checkpoint 沿用 8 字节有符号 int64）；字节串和字符串前加 u32 BE 长度前缀，字符串 UTF-8；每个结构以长度前缀域标签 `ZK-STATE-ANCHOR-01:<tag>` 开头；字段顺序固定，禁止 Rust Debug / JSON 字段顺序 / 平台相关序列化。

```
A_e = SHA256(domain("D_A") || u32be(version) || u64be(epoch) || u32be(policy_version)
             || bytes_with_len(GR) || bytes_with_len(RR) || bytes_with_len(A_{e-1}))

AnchorRecord_e = domain("AnchorRecord")
               || field("anchor", bytes_with_len(encode(anchor)))
               || field("anchor_digest", bytes_with_len(A_e))

Leaf_e = SHA256(domain("D_L") || bytes_with_len(AnchorRecord_e))
```

日志为 RFC 6962 风格：叶子 `SHA256(0x00||leaf)`、内部节点 `SHA256(0x01||left||right)`，非 2 幂大小按严格小于 n 的最大 2 幂递归分割；测试向量使用 3 个叶子。

D1-E adapter 已逐行核查原仓库 `canonical.py:11-72`、`crypto.py:25-26,50-60`、`quorum.py:45-98`、`merkle.py:18-94`、`gateway.py:21-47` 后镜像，未修改原仓库。D1-E 的长度前缀为 **8 字节大端**（与 D2-B 自身结构的 4 字节前缀不同）；用 `src/bin/encoding_probe.rs` 与 D1-E Python 对同一 checkpoint 逐字节比对，编码 SHA-256 双方均为 `6db36b29a17d0afadfc1c2a4fac3775f05027e030eb78f4d2c259cd30abc25d7`。

## 3. `state_root` / `log_root` / `anchor_digest` 三者关系

| 名称 | 来源 | 承诺对象 |
| --- | --- | --- |
| `state_root` | D1-E | 授权事件历史的 SHA-256 状态承诺（原有字段，本轮不改） |
| `log_root` | D1-E 透明日志 | RFC 6962 Merkle Root，包含 `AnchorRecord_e` 叶子 |
| `anchor_digest` | D2-B | GR/RR/epoch/policy/前驱锚点的 SHA-256 外部摘要 |

可验证关系：`anchor_digest` 从 anchor 重算一致 → `AnchorRecord` 确定性生成 `Leaf_e` → inclusion proof 证明 `Leaf_e ∈ MerkleLog(log_root)` → 验证者持有的 `checkpoint.log_root` 与该证明根一致 → QC 签名覆盖该 checkpoint → Halo2 public inputs 的 GR/RR 逐字节等于 anchor 的 GR/RR。

**明确不声称**：仅凭 AnchorRecord 在日志中，就证明它和 `state_root` 对应的完整语义状态一致。该语义绑定不是本轮证明的安全属性。

## 4. QC 验证具体覆盖字段

按 D1-E `quorum.py`，QC 验证检查 `checkpoint_hash`、`epoch`、`previous_hash`、至少 3 个不同 witness_id，以及每个 witness 对**完整 checkpoint 编码**的 Ed25519 签名。该编码覆盖 `chain_id`、`epoch`、`previous_hash`、`state_root`、`log_root`、`policy_version`、`witness_set_root`、`log_size`、`timestamp`。

R1 起测试签名器 `TestQuorumSigner` 只用于构造 QC，验证器不再接收签名器；生产验证输入是 `TrustedWitnessSet`（显式公钥 + 阈值 + 带外期望根）。验签前先核对集合根与 `checkpoint.witness_set_root`，再检查 ID 唯一性、阈值、集合成员身份与 Ed25519 签名。不重新实现 D1-E 签名锁定表。

## 5. Freshness Provider 的信任假设

| Provider | 行为 | 本轮含义 |
| --- | --- | --- |
| `HonestFreshnessProvider` | 返回当前最新 checkpoint | 验证器接受与其匹配的 presented checkpoint |
| `StaleFreshnessProvider` | 返回历史 checkpoint | 冷启动客户端必须拒绝（T16） |
| `UnavailableFreshnessProvider` | 返回错误 | 一律拒绝，不回退到“有 QC 就接受”（T17） |

R1 起判定改为结构化：`TrustedCheckpoint.epoch` 与 `checkpoint_hash` 必须同时等于 presented checkpoint；失败关闭且不读取 trace 字符串。最新性来自外部信任假设，不是 Merkle/QC 的内部属性。测试 Provider 均为模拟，不连接真实服务，不宣称生产级 freshness。

## 6. T01–T20 完整测试结果

| 编号 | 场景 | 预期 | 实际 | 结论 |
| --- | --- | --- | --- | --- |
| T01 | 正常 anchor + 有效 QC + inclusion | ACCEPT | ACCEPT | PASS |
| T02 * | 修改 grant_root | PUBLIC_INPUT_MISMATCH | PUBLIC_INPUT_MISMATCH | PASS |
| T03 * | 修改 revoke_root | PUBLIC_INPUT_MISMATCH | PUBLIC_INPUT_MISMATCH | PASS |
| T04 * | 修改 epoch | ANCHOR_EPOCH_MISMATCH | ANCHOR_EPOCH_MISMATCH | PASS |
| T05 * | 修改 policy_version | POLICY_VERSION_MISMATCH | POLICY_VERSION_MISMATCH | PASS |
| T06 | 修改 prev_anchor_digest | INVALID_PREDECESSOR | INVALID_PREDECESSOR | PASS |
| T07 | 伪造 anchor_digest | INVALID_ANCHOR_DIGEST | INVALID_ANCHOR_DIGEST | PASS |
| T08 * | 日志 inclusion proof 错误 | INVALID_LOG_INCLUSION | INVALID_LOG_INCLUSION | PASS |
| T09 | 使用其他日志的 inclusion proof | INVALID_LOG_INCLUSION | INVALID_LOG_INCLUSION | PASS |
| T10 * | QC 签名无效 | INVALID_QUORUM_CERTIFICATE | INVALID_QUORUM_CERTIFICATE | PASS |
| T11 | QC quorum 不足 | INVALID_QUORUM_CERTIFICATE | INVALID_QUORUM_CERTIFICATE | PASS |
| T12 | checkpoint 前驱哈希不匹配 | CHECKPOINT_GAP | CHECKPOINT_GAP | PASS |
| T13 | checkpoint epoch 倒退 | ANCHOR_EPOCH_MISMATCH | ANCHOR_EPOCH_MISMATCH | PASS |
| T14 * | 客户端已见更新 checkpoint，尝试回滚 | CHECKPOINT_ROLLBACK | CHECKPOINT_ROLLBACK | PASS |
| T15 | 冷启动 + freshness 返回最新 | ACCEPT | ACCEPT | PASS |
| T16 * | 冷启动 + freshness 返回旧 checkpoint | FRESHNESS_UNAVAILABLE | FRESHNESS_UNAVAILABLE | PASS |
| T17 | freshness provider 不可用 | FRESHNESS_UNAVAILABLE | FRESHNESS_UNAVAILABLE | PASS |
| T18 * | Halo2 public inputs 与 anchor 不一致 | PUBLIC_INPUT_MISMATCH | PUBLIC_INPUT_MISMATCH | PASS |
| T19 | 旧 policy version | POLICY_VERSION_MISMATCH | POLICY_VERSION_MISMATCH | PASS |
| T20 | 修改日志中的 AnchorRecord 内容 | INVALID_LOG_INCLUSION | INVALID_LOG_INCLUSION | PASS |

* 标记项同时要求并记录具体失败原因：

- T02 → `PUBLIC_INPUT_MISMATCH`
- T03 → `PUBLIC_INPUT_MISMATCH`
- T04 → `ANCHOR_EPOCH_MISMATCH`
- T05 → `POLICY_VERSION_MISMATCH`
- T08 → `INVALID_LOG_INCLUSION`
- T10 → `INVALID_QUORUM_CERTIFICATE`
- T14 → `CHECKPOINT_ROLLBACK`
- T16 → `FRESHNESS_UNAVAILABLE`
- T18 → `PUBLIC_INPUT_MISMATCH`

全部 20 项实际结果与任务包预期一致；加入 R1 后 `cargo test --locked` 总测试数 47（4 库单测 + 43 集成测试），无失败。

## 7. 执行记录

### 7.1 正常路径（T01）

```
[1/10] anchor_record | OK | record.anchor == request.anchor
[1/10] anchor_digest | OK | computed=d6ab825ceee46d25dacbe3a7c721f9e7d96d4eae62192242d974a59f647537e9 provided=d6ab825ceee46d25dacbe3a7c721f9e7d96d4eae62192242d974a59f647537e9
[2/10] public_inputs | OK | GR_h2=00000000000000000000000000000000000000000000000000000000000003e9 GR_anchor=00000000000000000000000000000000000000000000000000000000000003e9 RR_h2=00000000000000000000000000000000000000000000000000000000000003ea RR_anchor=00000000000000000000000000000000000000000000000000000000000003ea
[3/10] epoch_binding | OK | anchor=8 checkpoint=8 expected=8
[3/10] policy_binding | OK | anchor=1 checkpoint=1 expected=1
[4/10] log_inclusion | OK | log_id=authz-log-1 index=1 size=3 cp_log_root=63c1daba4787f5a90834a2385a30f79384c4039ffe61928c5f25e710a8301625
[5/10] witness_set_binding | OK | computed_root=a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d expected_root=a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d checkpoint_root=a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d code=OK
[5/10] quorum_certificate | OK | signatures=3 detail=valid
[6/10] checkpoint_fields | OK | chain_id=authz-chain-1 state_root=8bc9bfca4ef985be110271fe70370d560e3c531d5c146ea5bb328b634d97fa41 log_root=63c1daba4787f5a90834a2385a30f79384c4039ffe61928c5f25e710a8301625 sizes_match=true
[7/10] no_rollback | OK | known_epoch=7 offered_epoch=8
[7/10] checkpoint_chain | OK | previous_hash=2ed224e4e48beac7770bef206b28347692f6b0c5f71b26a15a3d90e364864941 known=2ed224e4e48beac7770bef206b28347692f6b0c5f71b26a15a3d90e364864941
[8/10] anchor_predecessor | OK | anchor_prev=a8ebc7656a314ad2a725c60cf45c369a41e582942f5ed47c2d0767a2f3364beb trusted_prev=a8ebc7656a314ad2a725c60cf45c369a41e582942f5ed47c2d0767a2f3364beb
[9/10] freshness | OK | HonestFreshnessProvider latest_epoch=8 offered_epoch=8 latest_hash=6c5a93e0f73a0102610c41fda8b10474aea9867d73a3c9985f7bbd787aa09591 offered_hash=6c5a93e0f73a0102610c41fda8b10474aea9867d73a3c9985f7bbd787aa09591 epoch_match=true hash_match=true match=true
[10/10] all_checks | OK | all nine checks passed
VERDICT: ACCEPT
```

### 7.2 回滚攻击（T14）

```
[1/10] anchor_record | OK | record.anchor == request.anchor
[1/10] anchor_digest | OK | computed=d6ab825ceee46d25dacbe3a7c721f9e7d96d4eae62192242d974a59f647537e9 provided=d6ab825ceee46d25dacbe3a7c721f9e7d96d4eae62192242d974a59f647537e9
[2/10] public_inputs | OK | GR_h2=00000000000000000000000000000000000000000000000000000000000003e9 GR_anchor=00000000000000000000000000000000000000000000000000000000000003e9 RR_h2=00000000000000000000000000000000000000000000000000000000000003ea RR_anchor=00000000000000000000000000000000000000000000000000000000000003ea
[3/10] epoch_binding | OK | anchor=8 checkpoint=8 expected=8
[3/10] policy_binding | OK | anchor=1 checkpoint=1 expected=1
[4/10] log_inclusion | OK | log_id=authz-log-1 index=1 size=3 cp_log_root=63c1daba4787f5a90834a2385a30f79384c4039ffe61928c5f25e710a8301625
[5/10] witness_set_binding | OK | computed_root=a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d expected_root=a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d checkpoint_root=a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d code=OK
[5/10] quorum_certificate | OK | signatures=3 detail=valid
[6/10] checkpoint_fields | OK | chain_id=authz-chain-1 state_root=8bc9bfca4ef985be110271fe70370d560e3c531d5c146ea5bb328b634d97fa41 log_root=63c1daba4787f5a90834a2385a30f79384c4039ffe61928c5f25e710a8301625 sizes_match=true
[7/10] no_rollback | FAIL | known_epoch=9 offered_epoch=8
VERDICT: REJECT CHECKPOINT_ROLLBACK
```

T14 在客户端高水位检查处早停，未进入 freshness 步骤；失败原因是 `CHECKPOINT_ROLLBACK`，不是 inclusion 或 QC 失败。

## 8. 关键安全边界

- QC 只证明 quorum 认证，不证明最新性；网络分区下不保证最新，按 fail-closed 处理。
- 客户端本地最高 epoch 只防止已见过的 checkpoint 被回滚；冷启动必须依赖外部 freshness。
- 本地最高 epoch 不能证明冷启动客户端拿到的是最新状态。
- inclusion proof 只证明记录在该树中，不证明树最新，也不证明记录语义正确。
- 本轮结果是系统集成原型，不宣称新的密码学原语或新的可证明安全属性。

## 9. 尚未解决的安全问题

1. GR/RR 与 D1-E `state_root` 背后事件历史的**语义绑定缺口**：本轮只验证字节匹配、日志包含、QC 认证，不验证构造过程；责任仍在授权注册表构建者（外部假设）。
2. anchor digest 使用 SHA-256 以复用 D1-E，未在 Halo2 电路内验证；若需电路内验证需另做 Poseidon 版本或桥接。
3. freshness 由测试 Provider 模拟，未接入真实服务，不构成生产最新性保证。
4. D2-B 只验证 QC 结果，不重新实现 D1-E 的见证者签名锁定与 split-view 检测。
5. ALLOW ≠ DENY：本轮不涉及不存在性证明；Ed25519 公钥只按带外可信集合匹配，不验证现实世界身份。

## 10. 复现

```bash
cargo test --locked -- --nocapture
cargo run --bin evidence
python tools/export_report.py
```

原始逐项结果与完整轨迹见 `results/verification_results.json`；完整测试日志见 `results/test_log.txt`。

## 11. EXP-D2-B-R1 增补：可信见证者集合绑定与结构化 Freshness

R1 只修复两个边界问题，不重做 D2-B、不扩展协议、不修改 D1-E/D2-A：

1. QC 验签所用公钥集合必须等于 checkpoint 声明并由带外配置固定的 `witness_set_root`；
2. Freshness 判定改为结构化结果比较，不使用 `freshness_detail.contains("match=true")`。

### 11.1 修改要点

- `VerifyRequest.signer: Arc<QuorumSigner>` 替换为 `trusted_witness_set: TrustedWitnessSet`；验证器只接收公钥，不持有签名私钥，不从公开 seed 派生密钥。
- `QuorumSigner` 改名 `TestQuorumSigner`，构造入口 `new_test_signer()`；公开 seed `EXP-D1-E-fixed-seed-v1` 仅用于测试密钥，生产集合必须带外提供。
- witness set root 严格复用 D1-E `canonical.py:86-90` / `crypto.py:33-34`：公钥 hex 字典序排序、每项 8 字节大端长度前缀 + UTF-8、无域标签、SHA-256；不是公钥字节直接拼接。
- 验签顺序：集合绑定 → checkpoint_hash/epoch/previous_hash → witness ID 唯一 → threshold → 集合成员 → Ed25519；失败保留细分错误码，验证器对外仍归一为 `INVALID_QUORUM_CERTIFICATE`，trace 中给出细分码。
- 重复 witness ID 直接拒绝，即使重复的是同一条有效签名。
- freshness 从 `TrustedCheckpoint` 的 `epoch` 与 `checkpoint_hash` 双字段判定；epoch 错或 hash 错或 provider 不可用均拒绝；trace 文本不参与决策。

### 11.2 W01–W10 见证者集合攻击矩阵

| 编号 | 攻击或场景 | 预期 | 实际 | 细分错误码 |
| --- | --- | --- | --- | --- |
| W01 | 正确 witness set + 正确 QC | ACCEPT | ACCEPT | `OK` |
| W02 | checkpoint.witness_set_root 被替换 | REJECT | REJECT | `WITNESS_SET_ROOT_MISMATCH` |
| W03 | 替换一把公钥，仍使用原 QC | REJECT | REJECT | `WITNESS_SET_ROOT_MISMATCH` |
| W04 | 未授权 witness ID 签名 | REJECT | REJECT | `UNTRUSTED_WITNESS_ID` |
| W05 | 重复 witness ID 不重复计票 | REJECT | REJECT | `DUPLICATE_WITNESS_ID` |
| W06 | 只有两个有效签名 | REJECT | REJECT | `INSUFFICIENT_SIGNATURES` |
| W07 | 三个签名中一个被篡改 | REJECT | REJECT | `INVALID_SIGNATURE` |
| W08 | 公钥排序顺序改变 | ROOT_UNCHANGED | ROOT_UNCHANGED | `OK` |
| W09 | Rust 根须等于 Python 根，错误编码不等价 | MATCH | MATCH | `OK` |
| W10 | 普通的不同 witness set 替换 | REJECT | REJECT | `WITNESS_SET_ROOT_MISMATCH` |

### 11.3 F01–F06 结构化 Freshness 矩阵

| 编号 | 场景 | 预期 | 实际 | 验证器原因码 |
| --- | --- | --- | --- | --- |
| F01 | 正确 epoch + 正确 hash | ACCEPT | ACCEPT | `ACCEPT` |
| F02 | 旧 epoch + 旧 hash | REJECT | REJECT | `FRESHNESS_UNAVAILABLE` |
| F03 | 正确 epoch + 错误 hash | REJECT | REJECT | `FRESHNESS_UNAVAILABLE` |
| F04 | 错误 epoch + 正确 hash | REJECT | REJECT | `FRESHNESS_UNAVAILABLE` |
| F05 | Provider 不可用 | REJECT | REJECT | `FRESHNESS_UNAVAILABLE` |
| F06 | 结果与日志文本无关 | ACCEPT | ACCEPT | `ACCEPT` |

### 11.4 Python / Rust witness set root 对照

- 来源：authorization-state-trust-exp/src/canonical.py::encode_witness_set + src/crypto.py::witness_set_root
- 向量文件：`tests/vectors/witness_set_vectors.json`（4 个 witness ID、4 个公钥、排序前后顺序、双方 root）
- Python root：`a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d`
- Rust root：`a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d`
- 逐字节一致：true
- 编码语义：4 个 Ed25519 原始公钥 hex 字符串按字典序排序；每项 8 字节大端长度前缀 + UTF-8；无域标签；SHA-256

### 11.5 测试密钥的安全边界

向量与测试 QC 使用的 Ed25519 私钥来自公开测试 seed，可被任何人重算，**不具备机密性**；它们只用于可复现实验与攻击矩阵。验证器结构中没有私钥字段，验证路径没有 seed 派生调用；生产部署必须由带外可信配置提供 4 个公钥、阈值 3 与期望根，不能把测试 signer 或 QC 自带的公钥当作信任来源。

### 11.6 R1 后仍未解决

- GR/RR 与 D1-E `state_root` 背后事件历史的语义绑定缺口仍在；这是下一步要攻克的 ZKP 问题。
- 未接入真实 Remote Witness Service 与网络级 freshness；freshness 仍是外部信任假设。
- 未实现 Halo2 内部 anchor 电路、未修改 D1-E 签名锁定与持久化、未改 3-of-4 参数、未改 RFC6962。
- 本轮是信任链严谨化，不是论文创新或新的密码学安全证明。
