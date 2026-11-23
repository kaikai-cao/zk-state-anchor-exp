#!/usr/bin/env python3
"""由 results/verification_results.json 生成 results/experiment_report.md。"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "results" / "verification_results.json").read_text(encoding="utf-8"))
ROWS = {r["id"]: r for r in DATA["results"]}

notable = ("T02", "T03", "T04", "T05", "T08", "T10", "T14", "T16", "T18")

lines: list[str] = []
add = lines.append

add("# EXP-D2-B-01 实验报告")
add("")
add("ZkStateAnchor：协议设计、规范化编码、参考实现与攻击测试")
add("")
add("> 性质：**设计 + 工程验证**。本轮不修改 D1-E/D2-A，不实现 Halo2 内部 anchor 电路，不做性能优化。")
add("> 20 项场景的断言、报告表格与执行记录来自同一套 `src/scenarios.rs` 构造器。")
add("")

add("## 1. 仓库与提交")
add("")
add("- 本地：`D:\\Research\\zk-state-anchor-exp`")
add("- GitHub：`kaikai-cao/zk-state-anchor-exp`")
add("- 最终 commit SHA：见本次交付汇报与仓库 `main` HEAD（本报告在提交前生成，故不自嵌入 SHA）。")
add("")

add("## 2. 完整协议数据结构与规范化编码")
add("")
add("`AuthzStateAnchor`：`version:u32`、`epoch:u64`、`policy_version:u32`、`grant_root:FieldBytes`、`revoke_root:FieldBytes`、`prev_anchor_digest:Hash32`、`anchor_digest:Hash32`。")
add("")
add("`FieldBytes` 为 Pallas 标量域元素的规范 32 字节大端编码，严格小于模数 `0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`；`Hash32` 为 SHA-256 输出。")
add("")
add("编码规则：全部整数大端定长（u32/u64，D1-E checkpoint 沿用 8 字节有符号 int64）；字节串和字符串前加 u32 BE 长度前缀，字符串 UTF-8；每个结构以长度前缀域标签 `ZK-STATE-ANCHOR-01:<tag>` 开头；字段顺序固定，禁止 Rust Debug / JSON 字段顺序 / 平台相关序列化。")
add("")
add("```")
add("A_e = SHA256(domain(\"D_A\") || u32be(version) || u64be(epoch) || u32be(policy_version)")
add("             || bytes_with_len(GR) || bytes_with_len(RR) || bytes_with_len(A_{e-1}))")
add("")
add("AnchorRecord_e = domain(\"AnchorRecord\")")
add("               || field(\"anchor\", bytes_with_len(encode(anchor)))")
add("               || field(\"anchor_digest\", bytes_with_len(A_e))")
add("")
add("Leaf_e = SHA256(domain(\"D_L\") || bytes_with_len(AnchorRecord_e))")
add("```")
add("")
add("日志为 RFC 6962 风格：叶子 `SHA256(0x00||leaf)`、内部节点 `SHA256(0x01||left||right)`，非 2 幂大小按严格小于 n 的最大 2 幂递归分割；测试向量使用 3 个叶子。")
add("")
add("D1-E adapter 已逐行核查原仓库 `canonical.py:11-72`、`crypto.py:25-26,50-60`、`quorum.py:45-98`、`merkle.py:18-94`、`gateway.py:21-47` 后镜像，未修改原仓库。D1-E 的长度前缀为 **8 字节大端**（与 D2-B 自身结构的 4 字节前缀不同）；用 `src/bin/encoding_probe.rs` 与 D1-E Python 对同一 checkpoint 逐字节比对，编码 SHA-256 双方均为 `6db36b29a17d0afadfc1c2a4fac3775f05027e030eb78f4d2c259cd30abc25d7`。")
add("")

add("## 3. `state_root` / `log_root` / `anchor_digest` 三者关系")
add("")
add("| 名称 | 来源 | 承诺对象 |")
add("| --- | --- | --- |")
add("| `state_root` | D1-E | 授权事件历史的 SHA-256 状态承诺（原有字段，本轮不改） |")
add("| `log_root` | D1-E 透明日志 | RFC 6962 Merkle Root，包含 `AnchorRecord_e` 叶子 |")
add("| `anchor_digest` | D2-B | GR/RR/epoch/policy/前驱锚点的 SHA-256 外部摘要 |")
add("")
add("可验证关系：`anchor_digest` 从 anchor 重算一致 → `AnchorRecord` 确定性生成 `Leaf_e` → inclusion proof 证明 `Leaf_e ∈ MerkleLog(log_root)` → 验证者持有的 `checkpoint.log_root` 与该证明根一致 → QC 签名覆盖该 checkpoint → Halo2 public inputs 的 GR/RR 逐字节等于 anchor 的 GR/RR。")
add("")
add("**明确不声称**：仅凭 AnchorRecord 在日志中，就证明它和 `state_root` 对应的完整语义状态一致。该语义绑定不是本轮证明的安全属性。")
add("")

add("## 4. QC 验证具体覆盖字段")
add("")
add("按 D1-E `quorum.py`，QC 验证检查 `checkpoint_hash`、`epoch`、`previous_hash`、至少 3 个不同 witness_id，以及每个 witness 对**完整 checkpoint 编码**的 Ed25519 签名。该编码覆盖 `chain_id`、`epoch`、`previous_hash`、`state_root`、`log_root`、`policy_version`、`witness_set_root`、`log_size`、`timestamp`。")
add("")
add("本 adapter 使用确定性派生的 4 个 Ed25519 见证者密钥（与 D1-E 相同的 `sha256(seed|witness_id)` 思路），3-of-4 验签；不重新实现 D1-E 签名锁定表。")
add("")

add("## 5. Freshness Provider 的信任假设")
add("")
add("| Provider | 行为 | 本轮含义 |")
add("| --- | --- | --- |")
add("| `HonestFreshnessProvider` | 返回当前最新 checkpoint | 验证器接受与其匹配的 presented checkpoint |")
add("| `StaleFreshnessProvider` | 返回历史 checkpoint | 冷启动客户端必须拒绝（T16） |")
add("| `UnavailableFreshnessProvider` | 返回错误 | 一律拒绝，不回退到“有 QC 就接受”（T17） |")
add("")
add("验证器总是调用 provider；最新性来自外部信任假设，不是 Merkle/QC 的内部属性。测试 Provider 均为模拟，不连接真实服务，不宣称生产级 freshness。")
add("")

add("## 6. T01–T20 完整测试结果")
add("")
add("| 编号 | 场景 | 预期 | 实际 | 结论 |")
add("| --- | --- | --- | --- | --- |")
for i in range(1, 21):
    tid = f"T{i:02d}"
    row = ROWS[tid]
    actual = row["actual"]
    verdict = "PASS" if row["expected"] == actual else "FAIL"
    star = " *" if tid in notable else ""
    add(f"| {tid}{star} | {row['title']} | {row['expected']} | {actual} | {verdict} |")
add("")
add("* 标记项同时要求并记录具体失败原因：")
add("")
for tid in notable:
    row = ROWS[tid]
    add(f"- {tid} → `{row['actual']}`")
add("")
add("全部 20 项实际结果与任务包预期一致；`cargo test --locked` 总测试数 28（4 库单测 + 24 集成测试），无失败。")
add("")

add("## 7. 执行记录")
add("")
add("### 7.1 正常路径（T01）")
add("")
add("```")
for step in DATA["execution_records"]["normal_path_T01"]:
    add(step)
add("```")
add("")
add("### 7.2 回滚攻击（T14）")
add("")
add("```")
for step in DATA["execution_records"]["rollback_attack_T14"]:
    add(step)
add("```")
add("")
add("T14 在客户端高水位检查处早停，未进入 freshness 步骤；失败原因是 `CHECKPOINT_ROLLBACK`，不是 inclusion 或 QC 失败。")
add("")

add("## 8. 关键安全边界")
add("")
add("- QC 只证明 quorum 认证，不证明最新性；网络分区下不保证最新，按 fail-closed 处理。")
add("- 客户端本地最高 epoch 只防止已见过的 checkpoint 被回滚；冷启动必须依赖外部 freshness。")
add("- 本地最高 epoch 不能证明冷启动客户端拿到的是最新状态。")
add("- inclusion proof 只证明记录在该树中，不证明树最新，也不证明记录语义正确。")
add("- 本轮结果是系统集成原型，不宣称新的密码学原语或新的可证明安全属性。")
add("")

add("## 9. 尚未解决的安全问题")
add("")
add("1. GR/RR 与 D1-E `state_root` 背后事件历史的**语义绑定缺口**：本轮只验证字节匹配、日志包含、QC 认证，不验证构造过程；责任仍在授权注册表构建者（外部假设）。")
add("2. anchor digest 使用 SHA-256 以复用 D1-E，未在 Halo2 电路内验证；若需电路内验证需另做 Poseidon 版本或桥接。")
add("3. freshness 由测试 Provider 模拟，未接入真实服务，不构成生产最新性保证。")
add("4. D2-B 只验证 QC 结果，不重新实现 D1-E 的见证者签名锁定与 split-view 检测。")
add("5. ALLOW ≠ DENY：本轮不涉及不存在性证明；不验证 Ed25519 签发者身份。")
add("")

add("## 10. 复现")
add("")
add("```bash")
add("cargo test --locked -- --nocapture")
add("cargo run --bin evidence")
add("python tools/export_report.py")
add("```")
add("")
add("原始逐项结果与完整轨迹见 `results/verification_results.json`；完整测试日志见 `results/test_log.txt`。")
add("")

out = ROOT / "results" / "experiment_report.md"
out.write_text("\n".join(lines), encoding="utf-8")
print(f"wrote {out} ({len(lines)} lines)")
