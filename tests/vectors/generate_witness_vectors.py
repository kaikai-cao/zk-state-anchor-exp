"""从 D1-E 原始 Python 函数生成可信见证者集合固定向量。

用法：
    python tests/vectors/generate_witness_vectors.py [D1-E 仓库根目录]

默认 D1-E 仓库根目录为 D:\\Research\\authorization-state-trust-exp。
本脚本只调用 D1-E 的 `derive_keypair` / `witness_set_root` / `encode_witness_set`，
不在本仓自行重算期望值；Rust 侧的 `witness_set.rs` 必须对同一向量给出相同 root。
"""

import json
import sys
from pathlib import Path

DEFAULT_D1E_ROOT = Path(r"D:\Research\authorization-state-trust-exp")
SEED = b"EXP-D1-E-fixed-seed-v1"  # 与 D1-E src/attacks.py:SEED 相同；仅测试密钥


def main() -> None:
    d1e_root = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_D1E_ROOT
    sys.path.insert(0, str(d1e_root))

    from src.canonical import encode_witness_set  # D1-E 原始实现
    from src.crypto import derive_keypair, witness_set_root  # D1-E 原始实现

    pairs = [derive_keypair(SEED, "W%d" % i) for i in range(1, 5)]
    pre_sort = [p.public_hex for p in pairs]
    post_sort = sorted(pre_sort)

    out = Path(__file__).resolve().parent / "witness_set_vectors.json"
    existing_rust_root = ""
    if out.exists():
        existing_rust_root = json.loads(out.read_text(encoding="utf-8")).get(
            "rust_witness_set_root", ""
        )

    vector = {
        "experiment": "EXP-D2-B-R1",
        "generated_from": {
            "repository": "authorization-state-trust-exp",
            "files": ["src/canonical.py", "src/crypto.py", "src/attacks.py"],
            "functions": ["derive_keypair", "encode_witness_set", "witness_set_root"],
            "seed_label": "EXP-D1-E-fixed-seed-v1",
        },
        "witnesses": [
            {"id": p.key_id, "public_key_hex": p.public_hex} for p in pairs
        ],
        "pre_sort_order": pre_sort,
        "post_sort_order": post_sort,
        "encoding_hex": encode_witness_set(pre_sort).hex(),
        "python_witness_set_root": witness_set_root(pre_sort),
        # 由 Rust 侧核对后填入；不得由 Rust 自行推导期望值。重新生成时保留已填值。
        "rust_witness_set_root": existing_rust_root,
    }

    out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out)
    print("python_witness_set_root=" + vector["python_witness_set_root"])


if __name__ == "__main__":
    main()
