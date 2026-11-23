//! D1-E checkpoint 格式的 Rust adapter。
//!
//! 已逐行核查 `authorization-state-trust-exp/src/canonical.py:11-72`：
//! - 前缀 b"EXP-D1-E:" + enc_str("Checkpoint")；
//! - 每字段为 enc_str(field_name) + 定长编码值；
//! - chain_id/state_root/log_root/policy_version/witness_set_root 为 str，
//!   epoch/log_size/timestamp 为 int64，previous_hash 为 str(hex)。
//!
//! 本轮不修改 D1-E 的 checkpoint 格式或 quorum 规则。

use crate::encoding::{int64be, sha256, u64be, Hash32};

pub const CHAIN_ID: &str = "authz-chain-1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub chain_id: String,
    pub epoch: u64,
    pub previous_hash: Hash32,
    pub state_root: Hash32,
    pub log_root: Hash32,
    pub policy_version: String,
    pub witness_set_root: Hash32,
    pub log_size: u64,
    pub timestamp: i64,
}

/// D1-E 的 enc_str：8 字节大端长度前缀 + UTF-8，不是 D2-B 自身的 4 字节前缀。
fn enc_str(v: &str) -> Vec<u8> {
    let raw = v.as_bytes();
    let mut out = Vec::with_capacity(8 + raw.len());
    out.extend_from_slice(&u64be(raw.len() as u64));
    out.extend_from_slice(raw);
    out
}

fn enc_int(v: i64) -> [u8; 8] {
    int64be(v)
}

fn enc_field(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = enc_str(name);
    out.extend_from_slice(value);
    out
}

/// 与 D1-E `encode_checkpoint` 逐字节一致的编码。
pub fn encode_d1e_checkpoint(cp: &Checkpoint) -> Vec<u8> {
    let mut out = b"EXP-D1-E:".to_vec();
    out.extend_from_slice(&enc_str("Checkpoint"));
    out.extend_from_slice(&enc_field("chain_id", &enc_str(&cp.chain_id)));
    out.extend_from_slice(&enc_field("epoch", &enc_int(cp.epoch as i64)));
    out.extend_from_slice(&enc_field("previous_hash", &enc_str(&cp.previous_hash.to_hex())));
    out.extend_from_slice(&enc_field("state_root", &enc_str(&cp.state_root.to_hex())));
    out.extend_from_slice(&enc_field("log_root", &enc_str(&cp.log_root.to_hex())));
    out.extend_from_slice(&enc_field("policy_version", &enc_str(&cp.policy_version)));
    out.extend_from_slice(&enc_field(
        "witness_set_root",
        &enc_str(&cp.witness_set_root.to_hex()),
    ));
    out.extend_from_slice(&enc_field("log_size", &enc_int(cp.log_size as i64)));
    out.extend_from_slice(&enc_field("timestamp", &enc_int(cp.timestamp)));
    out
}

/// 与 D1-E `checkpoint_hash = sha256_hex(encode_checkpoint(cp))` 一致。
pub fn checkpoint_hash(cp: &Checkpoint) -> Hash32 {
    sha256(&[&encode_d1e_checkpoint(cp)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Hash32;

    /// 该期望值由 D1-E 原仓 Python `encode_checkpoint`/`checkpoint_hash` 对同一
    /// checkpoint 计算得到，并用 `src/bin/encoding_probe.rs` 逐字节比对通过。
    #[test]
    fn d1e_encoding_matches_python_reference() {
        let cp = Checkpoint {
            chain_id: "c".to_string(),
            epoch: 1,
            previous_hash: Hash32([1u8; 32]),
            state_root: Hash32([2u8; 32]),
            log_root: Hash32([3u8; 32]),
            policy_version: "v1".to_string(),
            witness_set_root: Hash32([4u8; 32]),
            log_size: 2,
            timestamp: 5,
        };
        assert_eq!(
            checkpoint_hash(&cp).to_hex(),
            "096a1172958b01c6ed35d215127182a5e6bcac130d41c9ccd16e4fe922ee5014"
        );
    }
}
