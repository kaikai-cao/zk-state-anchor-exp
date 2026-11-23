# EXP-D2-B-01 — ZkStateAnchor 协议说明

## 1. 目标与信任链

D2-A 的 Halo2 proof 只能证明：给定公开的 `GR`（Grant Tree Root）和 `RR`（Revocation Tree Root），存在一条有效、未撤销、权限不扩大的两级授权路径。它**不能**证明这两个 Root 属于经过 quorum 认证的授权状态。

本实验在电路外建立一条可验证的信任链：

```
Halo2 Proof (GR, RR, Dq)
   → AuthzStateAnchor (A_e)
   → AnchorRecord_e ∈ RFC6962 Transparency Log (log_root)
   → Checkpoint_e (QC 签名覆盖 log_root, state_root, epoch, policy_version)
   → Freshness Provider attestation
   → ACCEPT / REJECT(reason)
```

本轮只实现外部验证器与参考数据结构；**不修改 Halo2 电路**，也**不把 SHA-256 放进电路**。

## 2. 数据结构

| 字段 | 类型 | 语义 |
| --- | --- | --- |
| `version` | u32 | 协议版本（本轮 `1`） |
| `epoch` | u64 | 授权状态版本（测试向量 `8`） |
| `policy_version` | u32 | 策略版本（测试向量 `1`，对应 D1-E 的字符串 `"1"`） |
| `grant_root` | FieldBytes | D2-A Poseidon Grant Tree Root 的规范 32B 大端编码 |
| `revoke_root` | FieldBytes | D2-A Poseidon Revocation Tree Root 的规范 32B 大端编码 |
| `prev_anchor_digest` | Hash32 | 前一个状态锚点摘要 |
| `anchor_digest` | Hash32 | 当前锚点摘要，由下列公式计算 |

`FieldBytes` 必须是规范域元素：32 字节大端，且严格小于 Pallas 标量域模数
`0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`。

`Hash32` 为 32 字节 SHA-256 输出。

## 3. 规范化编码

禁止 Rust `Debug`、JSON 字段顺序或平台相关序列化。所有结构使用：

- 域标签：`str_with_len("ZK-STATE-ANCHOR-01:<tag>")`（u32 BE 长度 + UTF-8）；
- 整数：`u32`/`u64` 大端定长；D1-E checkpoint 的整数沿用 8 字节有符号大端；
- 字节串：`u32 BE 长度 + bytes`；字符串：`u32 BE 长度 + UTF-8 bytes`；
- 字段顺序在代码中固定，不依赖结构体内存布局。

### 3.1 锚点摘要

```
A_e = SHA256(
    domain("D_A")
  || u32be(version) || u64be(epoch) || u32be(policy_version)
  || bytes_with_len(GR) || bytes_with_len(RR)
  || bytes_with_len(A_{e-1})
)
```

### 3.2 AnchorRecord 与日志叶子

```
AnchorRecord_e = domain("AnchorRecord")
               || field("anchor", bytes_with_len(encode(anchor)))
               || field("anchor_digest", bytes_with_len(A_e))

Leaf_e         = SHA256(domain("D_L") || bytes_with_len(AnchorRecord_e))
```

其中 `field(name, value) = str_with_len(name) || value`。

日志为 RFC 6962 风格：`leaf_hash = SHA256(0x00 || leaf)`，
`node_hash = SHA256(0x01 || left || right)`，非 2 的幂大小用
`k = 严格小于 n 的最大 2 幂` 递归分割；测试向量使用 3 个叶子以覆盖非 2 幂树形。

### 3.3 D1-E checkpoint 编码（adapter，未修改原仓库）

逐行核查了 `authorization-state-trust-exp` 的下列实现后再在 Rust 中镜像：

| 核查文件 | 内容 |
| --- | --- |
| `src/canonical.py:11-72` | `enc_str`/`enc_int`/`enc_bytes`、`encode_checkpoint` 的字段顺序与 `EXP-D1-E:` 前缀 |
| `src/crypto.py:25-26` | `checkpoint_hash = sha256_hex(encode_checkpoint(cp))` |
| `src/crypto.py:50-60` | Ed25519 私钥由 `sha256(seed || "|" || witness_id)` 确定性派生 |
| `src/quorum.py:45-98` | 3-of-4 QC：检查 `checkpoint_hash`、`epoch`、`previous_hash`、不同 witness_id 与 Ed25519 验签 |
| `src/merkle.py:18-94` | RFC 6962 叶子/内部节点哈希、inclusion proof 的方向推导与验证 |
| `src/gateway.py:21-47` | checkpoint 链连续、epoch 严格递增；内部检查不产生最新性 |

因此 `encode_d1e_checkpoint` 与 D1-E Python 端逐字节一致；QC 验签内容就是完整 checkpoint 编码。

注意 D1-E 的 `enc_str`/`enc_bytes` 长度前缀是 **8 字节大端**（不是 D2-B 自身结构的 4 字节前缀），整数也是 8 字节有符号大端。该差异已通过 `src/bin/encoding_probe.rs` 与 D1-E 原仓 Python 对同一 checkpoint 逐字节比对确认（编码 SHA-256 双方均为 `6db36b29a17d0afadfc1c2a4fac3775f05027e030eb78f4d2c259cd30abc25d7`，换行归一化后）。

### 3.4 可信见证者集合根（R1 新增）

严格复用 D1-E `src/canonical.py:86-90` 与 `src/crypto.py:33-34`，不是 D2-B 自定义编码：

```
witness_set_root = SHA256( concat( enc_str(k) for k in sorted(public_keys_hex) ) )
enc_str(k)       = u64be(len(utf8(k))) || utf8(k)      // 8 字节大端长度前缀
```

`public_keys_hex` 是 32 字节原始 Ed25519 公钥的小写 hex 字符串；排序按 Python `sorted()` 对 hex 字符串的字典序；**没有域标签**，不能套用 D2-B 自身的 u32 长度前缀规则。固定向量见 `tests/vectors/witness_set_vectors.json`，Python 与 Rust root 均为 `a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d`。

### 3.5 可信配置有效性（R2 新增）

生产配置入口为 `TrustedWitnessSet::from_trusted_config(entries, threshold, expected_root)`：

- `expected_root` 必须由调用方显式提供，构造时重新计算集合根；不一致直接拒绝初始化；
- 结构约束 `1 <= threshold <= n`，`n` 为唯一公钥数量；空集合、零阈值、阈值超限拒绝；
- witness ID 唯一，公钥唯一；不同 ID 复用同一把公钥在构造期拒绝，因为 QC 签名消息不含 witness ID，否则一把私钥可伪装成多个独立见证者；
- 测试构造器 `from_verifying_keys_for_tests` 标记为 test-only，仅供场景与测试使用，不能证明根来自带外配置；
- 验证器在 `check_binding` / `verify_qc` 前重新执行结构校验，防止配置对象被事后篡改形成零阈值空签名绕过。

默认研究参数仍为 **3-of-4**；1-of-4 / 4-of-4 只是合法配置边界测试，不改变实验协议参数。

## 4. `state_root` / `log_root` / `anchor_digest` 的关系

三者是**不同的承诺**，不能互相替代：

| 承诺 | 来源 | 承诺对象 |
| --- | --- | --- |
| `state_root` | D1-E | 授权事件历史的 SHA-256 状态承诺（原有字段，本轮不改动） |
| `log_root` | D1-E 透明日志 | RFC 6962 Merkle Root，包含 `AnchorRecord_e` 叶子 |
| `anchor_digest` | D2-B | 绑定 GR/RR/epoch/policy/前驱锚点的 SHA-256 外部摘要 |

可验证关系：

1. `anchor_digest == A_e(anchor)`；
2. `Leaf_e` 由 `AnchorRecord_e`（含 `anchor_digest`）确定性计算；
3. `Leaf_e ∈ MerkleLog(log_root)`，由 inclusion proof 验证；
4. 验证者持有的 `checkpoint.log_root` 必须等于该 inclusion proof 对应的根；
5. QC 签名覆盖该 checkpoint（因此间接认证 `log_root` 与 `state_root` 字段）；
6. Halo2 public inputs 的 GR/RR 必须逐字节等于 anchor 中的 GR/RR。

**明确不声称**：`anchor_digest` 或 `AnchorRecord` 在日志中出现，就证明它与 `state_root` 对应的事件历史语义一致。这个语义绑定不在本轮范围内（见 §8）。

## 5. 责任划分

| 角色 | 责任 |
| --- | --- |
| 授权注册表构建者（D2-A registry） | 保证 GR/RR 确实由同一份授权历史与撤销状态正确构造；本轮只接收其字节承诺，不验证构造过程 |
| Anchor 生成者 | 按规范编码生成 `A_e` 与 `AnchorRecord_e`，并追加到透明日志 |
| 见证者 | 对完整 D1-E checkpoint 签名（3-of-4），认证 `log_root`/`state_root`/epoch/policy/`witness_set_root` |
| Gateway / 验证者 | 持有带外可信公钥集合（无私钥），执行本轮验证，维护本地最高认可 checkpoint，调用外部 freshness provider |
| Freshness Provider | 外部可信地返回当前最新 checkpoint；本轮仅为测试模拟 |

## 6. 外部验证器

`verify_authz_state_anchor()` 输入：Halo2 public inputs、anchor、AnchorRecord、日志 inclusion proof、D1-E checkpoint、QC、**显式可信见证者集合 `TrustedWitnessSet`**、期望状态（链 ID / 日志 ID / epoch / policy / 可信前驱锚点）、客户端本地状态、Freshness Provider。验证器不接收签名器、不持有私钥、不从公开 seed 派生密钥；测试签名器 `TestQuorumSigner`（公开 seed）只用于构造测试 QC。

`TrustedWitnessSet` 包含 4 个 `TrustedWitness{id, public_key}`、`threshold=3` 和带外固定的 `expected_root`。验签前先计算当前集合根并要求 `computed_root == expected_root == checkpoint.witness_set_root`；不相等直接拒绝（`WITNESS_SET_ROOT_MISMATCH` / `TRUSTED_SET_ROOT_MISMATCH`）。随后检查 `checkpoint_hash`、`epoch`、`previous_hash`、witness ID 唯一（重复直接拒绝）、签名数量达到 threshold、每个 ID 属于可信集合、每条 Ed25519 签名有效。

顺序执行并返回带原因的拒绝：

1. `anchor_record` 与 `anchor_digest` 自洽 → `INVALID_ANCHOR_DIGEST` / `ANCHOR_RECORD_MISMATCH`
2. Halo2 GR/RR 与 anchor GR/RR 一致、字段规范 → `PUBLIC_INPUT_MISMATCH`
3. epoch / policy 绑定 → `ANCHOR_EPOCH_MISMATCH` / `POLICY_VERSION_MISMATCH`
4. 日志 inclusion（log_id、叶子、树大小、Merkle 根）→ `INVALID_LOG_INCLUSION`
5. 可信集合绑定 + 3-of-4 QC 验签 → `INVALID_QUORUM_CERTIFICATE`（trace 保留细分码）
6. checkpoint 自身字段（chain_id、log_size 与树大小）→ `CHECKPOINT_GAP`
7. 客户端单调性与链连续性 → `CHECKPOINT_ROLLBACK` / `CHECKPOINT_GAP`
8. 锚点前驱关系 → `INVALID_PREDECESSOR`
9. 外部 freshness 结构化判定 → `FRESHNESS_UNAVAILABLE`

freshness 判定只读取 `FreshnessProvider::get_latest_checkpoint()` 返回的 `TrustedCheckpoint` 结构：`epoch` 与 `checkpoint_hash` 必须同时等于 presented checkpoint；provider 不可用一律失败关闭。trace 中的 `match=true/false` 只是结果的可读回显，不参与判定，不再使用字符串 `contains` 决策。

全部通过才返回 ACCEPT。拒绝原因保留为枚举，不压成普通 `false`。

## 7. QC 与最新性

QC 只说明“3 个见证者认证了该 checkpoint”。它**不**说明该 checkpoint 是最新 checkpoint。

- 本地最高 epoch 只能防止**已见过**的 checkpoint 被回滚；
- 冷启动客户端没有本地高水位，只有 freshness provider 返回的可信最新 checkpoint 才能让其接受；
- freshness provider 不可用或返回旧 checkpoint 时一律拒绝，不回退到“有 QC 就接受”；
- 网络分区下的最新性不保证，按 fail-closed 处理。

## 8. 未解决的安全问题

1. **语义绑定缺口**：本轮验证 GR/RR 的字节等于 Halo2 public inputs、锚点在日志中、日志根被 QC 认证；但没有证明 GR/RR 与 D1-E `state_root` 背后的事件历史语义一致。该责任目前落在授权注册表构建者（外部假设），不是本轮证明的安全属性。
2. **SHA-256 不在电路内**：外部 anchor digest 使用 SHA-256 以复用 D1-E；若未来要在 Halo2 内验证 anchor，需要 Poseidon 版本或单独桥接，本轮未做。
3. **Freshness 是外部信任假设**：测试 Provider 不连接真实服务，不构成生产级最新性保证；R1 只修判定逻辑，未接入真实网络服务。
4. **见证者行为**：D2-B 只验证 QC 结果，不重新实现 D1-E 的签名锁定表；双签检测仍属 D1-E 层。R1 只保证公钥集合来自带外可信配置并与 checkpoint 绑定，不验证现实身份，也不实现 Remote Witness Service。
5. **ALLOW ≠ DENY**：本轮不涉及“不存在有效路径”的证明。
6. **测试密钥机密性**：公开 seed 派生的测试密钥可被任何人重算，只用于可复现实验；生产必须带外提供公钥与期望根。
