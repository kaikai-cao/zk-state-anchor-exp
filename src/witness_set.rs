//! 可信见证者集合绑定与配置校验（EXP-D2-B-R1 / R2）。
//!
//! 验证器只接收本模块定义的公钥集合，不持有签名私钥，也不从公开 seed 派生任何密钥。
//! `TestQuorumSigner` 保留在 `quorum.rs` 中，仅为测试签名工具；生产验证接口
//! `verifier::verify_authz_state_anchor` 不再接受签名器。
//!
//! witness set root 严格复用 D1-E 原始语义（`authorization-state-trust-exp`）：
//! - `src/canonical.py:86-90`：`ordered = sorted(public_keys_hex)`，
//!   每项 `enc_str(k)` = 8 字节大端长度前缀 + UTF-8；
//! - `src/crypto.py:33-34`：`witness_set_root = sha256_hex(encode_witness_set(...))`；
//! - 输入是 32 字节原始 Ed25519 公钥的 64 字符小写 hex 字符串。
//!
//! 注意：D1-E 这个函数**没有**域标签，不能套用 D2-B 自己的 u32 前缀规则。

use std::fmt;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::checkpoint::{checkpoint_hash, encode_d1e_checkpoint, Checkpoint};
use crate::encoding::{u64be, Hash32};
use crate::quorum::QuorumCertificate;

/// 一个被显式信任的见证者：只有身份和公钥，没有私钥字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedWitness {
    pub id: String,
    pub public_key: VerifyingKey,
}

impl TrustedWitness {
    /// D1-E `KeyPair.public_hex`：32 字节原始公钥的小写 hex。
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }
}

/// 验证器使用的显式信任配置。该结构由可信配置提供，不由 QC 或日志内容生成。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedWitnessSet {
    pub witnesses: Vec<TrustedWitness>,
    pub threshold: usize,
    /// 带外固定的期望根；与集合派生根、checkpoint 中的根三方比对。
    pub expected_root: Hash32,
}

/// 可信见证者集合配置错误（构造期即拒绝，不进入生产验证路径）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessSetConfigError {
    EmptyWitnessSet,
    ThresholdZero,
    ThresholdExceedsUniqueKeys,
    DuplicateWitnessId,
    DuplicatePublicKey,
    WitnessSetRootMismatch,
}

impl WitnessSetConfigError {
    pub fn code(self) -> &'static str {
        match self {
            WitnessSetConfigError::EmptyWitnessSet => "EMPTY_WITNESS_SET",
            WitnessSetConfigError::ThresholdZero => "THRESHOLD_ZERO",
            WitnessSetConfigError::ThresholdExceedsUniqueKeys => "THRESHOLD_EXCEEDS_UNIQUE_KEYS",
            WitnessSetConfigError::DuplicateWitnessId => "DUPLICATE_WITNESS_ID",
            WitnessSetConfigError::DuplicatePublicKey => "DUPLICATE_PUBLIC_KEY",
            WitnessSetConfigError::WitnessSetRootMismatch => "WITNESS_SET_ROOT_MISMATCH",
        }
    }
}

impl fmt::Display for WitnessSetConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for WitnessSetConfigError {}

impl From<WitnessSetConfigError> for QcError {
    fn from(value: WitnessSetConfigError) -> Self {
        QcError::InvalidWitnessSetConfig(value)
    }
}

/// QC 验证的详细错误码。验证器对外仍归一为 `INVALID_QUORUM_CERTIFICATE`，
/// 但 trace 中保留这些细分码，测试断言具体码而不是仅断言失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QcError {
    /// 集合在进入 QC 验签前已不满足配置约束（例如字段被事后篡改）。
    InvalidWitnessSetConfig(WitnessSetConfigError),
    /// 由当前公钥集合算出的根与配置中的 expected_root 不一致。
    TrustedSetRootMismatch,
    /// 由当前公钥集合算出的根与 checkpoint.witness_set_root 不一致。
    CheckpointWitnessSetRootMismatch,
    CheckpointHashMismatch,
    EpochMismatch,
    PreviousHashMismatch,
    DuplicateWitnessId,
    InsufficientSignatures,
    UntrustedWitnessId,
    InvalidSignature,
}

impl QcError {
    pub fn code(self) -> &'static str {
        match self {
            QcError::InvalidWitnessSetConfig(e) => e.code(),
            QcError::TrustedSetRootMismatch => "TRUSTED_SET_ROOT_MISMATCH",
            QcError::CheckpointWitnessSetRootMismatch => "WITNESS_SET_ROOT_MISMATCH",
            QcError::CheckpointHashMismatch => "QC_CHECKPOINT_HASH_MISMATCH",
            QcError::EpochMismatch => "QC_EPOCH_MISMATCH",
            QcError::PreviousHashMismatch => "QC_PREVIOUS_HASH_MISMATCH",
            QcError::DuplicateWitnessId => "DUPLICATE_WITNESS_ID",
            QcError::InsufficientSignatures => "INSUFFICIENT_SIGNATURES",
            QcError::UntrustedWitnessId => "UNTRUSTED_WITNESS_ID",
            QcError::InvalidSignature => "INVALID_SIGNATURE",
        }
    }
}

impl fmt::Display for QcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for QcError {}

impl TrustedWitnessSet {
    /// 生产配置入口：带外 expected_root 必须由调用方显式给出。
    ///
    /// 构造时重新计算集合根：`computed_root != expected_root` 拒绝初始化；
    /// 空集合、`threshold == 0`、`threshold > n`、重复 witness ID、单钥多 ID 同样拒绝。
    /// 本函数不会自行生成并信任 expected_root。
    pub fn from_trusted_config(
        entries: &[(String, VerifyingKey)],
        threshold: usize,
        expected_root: Hash32,
    ) -> Result<Self, WitnessSetConfigError> {
        let witnesses = Self::witnesses_from(entries);
        let set = Self {
            witnesses,
            threshold,
            expected_root,
        };
        set.validate_config()?;
        let computed = Self::root_of(&set.witnesses);
        if computed != expected_root {
            return Err(WitnessSetConfigError::WitnessSetRootMismatch);
        }
        Ok(set)
    }

    /// TEST-ONLY 兼容入口：仅供既有测试与场景构造器使用，会自行计算 expected_root，
    /// 因此不能证明该根来自带外可信配置。生产验证路径禁止调用。
    #[doc(hidden)]
    pub fn from_verifying_keys(entries: &[(String, VerifyingKey)], threshold: usize) -> Self {
        Self::from_verifying_keys_for_tests(entries, threshold)
    }

    /// TEST-ONLY：仅供测试与场景构造器使用，会自行计算 expected_root，
    /// 因此不能证明该根来自带外可信配置。生产验证路径禁止调用。
    #[doc(hidden)]
    pub fn from_verifying_keys_for_tests(
        entries: &[(String, VerifyingKey)],
        threshold: usize,
    ) -> Self {
        let witnesses = Self::witnesses_from(entries);
        let expected_root = Self::root_of(&witnesses);
        let set = Self {
            witnesses,
            threshold,
            expected_root,
        };
        set.validate_config()
            .expect("test-only witness set must be structurally valid");
        set
    }

    fn witnesses_from(entries: &[(String, VerifyingKey)]) -> Vec<TrustedWitness> {
        entries
            .iter()
            .map(|(id, public_key)| TrustedWitness {
                id: id.clone(),
                public_key: *public_key,
            })
            .collect()
    }

    /// 结构约束：`1 <= threshold <= n`，ID 唯一，公钥唯一。
    /// 验证器在验签前也重新检查，防止配置对象被事后篡改。
    pub fn validate_config(&self) -> Result<(), WitnessSetConfigError> {
        if self.witnesses.is_empty() {
            return Err(WitnessSetConfigError::EmptyWitnessSet);
        }
        if self.threshold == 0 {
            return Err(WitnessSetConfigError::ThresholdZero);
        }

        let mut ids = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        for w in &self.witnesses {
            if !ids.insert(w.id.as_str()) {
                return Err(WitnessSetConfigError::DuplicateWitnessId);
            }
            if !keys.insert(w.public_key.to_bytes()) {
                return Err(WitnessSetConfigError::DuplicatePublicKey);
            }
        }
        if self.threshold > keys.len() {
            return Err(WitnessSetConfigError::ThresholdExceedsUniqueKeys);
        }
        Ok(())
    }

    pub fn compute_root(&self) -> Hash32 {
        Self::root_of(&self.witnesses)
    }

    /// 与 D1-E `encode_witness_set` 逐字节一致：排序的是 hex 字符串，
    /// 每项前缀是 8 字节大端长度，无域标签。
    pub fn encode_root_input(public_keys_hex: &[String]) -> Vec<u8> {
        let mut ordered = public_keys_hex.to_vec();
        ordered.sort();
        let mut out = Vec::new();
        for key in ordered {
            out.extend_from_slice(&u64be(key.len() as u64));
            out.extend_from_slice(key.as_bytes());
        }
        out
    }

    fn root_of(witnesses: &[TrustedWitness]) -> Hash32 {
        let keys: Vec<String> = witnesses
            .iter()
            .map(TrustedWitness::public_key_hex)
            .collect();
        let input = Self::encode_root_input(&keys);
        let mut h = Sha256::new();
        h.update(&input);
        let bytes: [u8; 32] = h.finalize().into();
        Hash32(bytes)
    }

    /// 在验签之前强制检查配置结构并绑定 checkpoint 声明的见证者集合。
    pub fn check_binding(&self, cp: &Checkpoint) -> Result<(), QcError> {
        self.validate_config()?;
        let computed = self.compute_root();
        if computed != self.expected_root {
            return Err(QcError::TrustedSetRootMismatch);
        }
        if computed != cp.witness_set_root {
            return Err(QcError::CheckpointWitnessSetRootMismatch);
        }
        Ok(())
    }

    /// 显式可信集合下的 QC 验证。顺序：配置校验 + 集合绑定 → QC 字段 → ID 唯一 →
    /// 阈值 → 集合成员身份 → Ed25519 验签。任何一步失败都返回具体错误码。
    pub fn verify_qc(&self, qc: &QuorumCertificate, cp: &Checkpoint) -> Result<(), QcError> {
        self.check_binding(cp)?;

        if qc.checkpoint_hash != checkpoint_hash(cp) {
            return Err(QcError::CheckpointHashMismatch);
        }
        if qc.epoch != cp.epoch {
            return Err(QcError::EpochMismatch);
        }
        if qc.previous_hash != cp.previous_hash {
            return Err(QcError::PreviousHashMismatch);
        }

        let data = encode_d1e_checkpoint(cp);
        let mut seen: Vec<&str> = Vec::new();
        let mut distinct: Vec<(&str, &[u8; 64])> = Vec::new();
        for (id, sig) in &qc.signatures {
            if seen.contains(&id.as_str()) {
                // 重复 ID 直接拒绝，即使重复提交的是同一条有效签名。
                return Err(QcError::DuplicateWitnessId);
            }
            seen.push(id.as_str());
            distinct.push((id.as_str(), sig));
        }
        if distinct.len() < self.threshold {
            return Err(QcError::InsufficientSignatures);
        }

        for (id, sig_bytes) in distinct {
            let witness = self
                .witnesses
                .iter()
                .find(|w| w.id == id)
                .ok_or(QcError::UntrustedWitnessId)?;
            let sig = Signature::from_bytes(sig_bytes);
            if witness.public_key.verify(&data, &sig).is_err() {
                return Err(QcError::InvalidSignature);
            }
        }
        Ok(())
    }
}
