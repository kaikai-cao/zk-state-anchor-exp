//! 确定性编码与外部 SHA-256 原语。
//!
//! 规则（禁止 Rust Debug / JSON 字段顺序 / 平台相关序列化）：
//! - 所有整数大端定长编码：u32 = 4B，u64 = 8B，D1-E 的 int64 = 8B 有符号；
//! - 字节串与字符串前加 u32 BE 长度前缀；字符串按 UTF-8；
//! - 每个数据结构先写长度前缀的域标签（domain tag），再按固定字段顺序写值。

use hex::FromHex;
use sha2::{Digest, Sha256};

/// Pallas 标量域（D2-A 中 GR/RR 所属域）的模数，大端 32 字节。
/// 用于检查 FieldBytes 是否是规范域元素表示，避免把越界 32 字节串当作域元素。
pub const PALLAS_BASE_MODULUS_HEX: &str =
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001";

pub const DOMAIN_PREFIX: &str = "ZK-STATE-ANCHOR-01";

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldBytes(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    InvalidLength { expected: usize, got: usize },
    InvalidHex,
    NonCanonicalField,
}

impl FieldBytes {
    /// 由小整数构造规范域元素（测试向量使用；真实值来自 D2-A Poseidon 输出）。
    pub fn from_u64(v: u64) -> Self {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&v.to_be_bytes());
        FieldBytes(b)
    }

    pub fn from_bytes(b: [u8; 32]) -> Result<Self, EncodeError> {
        let s = Self(b);
        if s.is_canonical() {
            Ok(s)
        } else {
            Err(EncodeError::NonCanonicalField)
        }
    }

    pub fn from_hex(s: &str) -> Result<Self, EncodeError> {
        let raw = Vec::from_hex(s).map_err(|_| EncodeError::InvalidHex)?;
        if raw.len() != 32 {
            return Err(EncodeError::InvalidLength {
                expected: 32,
                got: raw.len(),
            });
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        Self::from_bytes(b)
    }

    pub fn is_canonical(&self) -> bool {
        let modulus = Vec::from_hex(PALLAS_BASE_MODULUS_HEX).expect("constant modulus");
        self.0.as_slice() < modulus.as_slice()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Hash32 {
    pub fn from_label(label: &str) -> Self {
        let mut payload = domain("TEST-LABEL");
        payload.extend_from_slice(&str_with_len(label));
        Hash32(sha256(&[&payload]).0)
    }

    pub fn from_hex(s: &str) -> Result<Self, EncodeError> {
        let raw = Vec::from_hex(s).map_err(|_| EncodeError::InvalidHex)?;
        if raw.len() != 32 {
            return Err(EncodeError::InvalidLength {
                expected: 32,
                got: raw.len(),
            });
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        Ok(Hash32(b))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for FieldBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FieldBytes({})", self.to_hex())
    }
}

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

pub fn u32be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

pub fn u64be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// D1-E 的 enc_int：int64 有符号大端 8 字节。本实验所有值非负，但编码保持一致。
pub fn int64be(v: i64) -> [u8; 8] {
    v.to_be_bytes()
}

pub fn bytes_with_len(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + b.len());
    out.extend_from_slice(&u32be(b.len() as u32));
    out.extend_from_slice(b);
    out
}

pub fn str_with_len(s: &str) -> Vec<u8> {
    bytes_with_len(s.as_bytes())
}

/// 返回带长度前缀的完整域标签，例如 "ZK-STATE-ANCHOR-01:D_A"。
pub fn domain(tag: &str) -> Vec<u8> {
    str_with_len(&format!("{}:{}", DOMAIN_PREFIX, tag))
}

pub fn sha256(parts: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    Hash32(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_bytes_reject_non_canonical_value() {
        let max = Vec::from_hex(PALLAS_BASE_MODULUS_HEX).unwrap();
        let bad = FieldBytes(max.try_into().unwrap());
        assert!(!bad.is_canonical());
        assert!(FieldBytes::from_u64(1).is_canonical());
    }

    #[test]
    fn domain_encoding_is_stable() {
        assert_eq!(domain("D_A"), domain("D_A"));
        assert_ne!(domain("D_A"), domain("D_L"));
    }
}
