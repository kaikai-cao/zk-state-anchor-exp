//! 测试签名工具（不是生产验证接口）。
//!
//! D2-B-R1 起，验证器只接收 `witness_set::TrustedWitnessSet`（公钥 + 阈值 + 带外期望根）。
//! 本文件的 `TestQuorumSigner` 使用公开测试 seed 派生 Ed25519 私钥，**只用于构造测试 QC**，
//! 任何生产验证路径都不得调用；公开 seed 派生私钥不构成安全密钥管理。
//!
//! 核查来源：D1-E `src/quorum.py:45-98` 与 `src/crypto.py:50-60`。签名内容为
//! D1-E 完整 checkpoint 编码。本轮不实现 D1-E 的签名锁定表。

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::checkpoint::{checkpoint_hash, encode_d1e_checkpoint, Checkpoint};
use crate::encoding::Hash32;

pub const THRESHOLD: usize = 3;
pub const WITNESS_COUNT: usize = 4;
/// 与 D1-E `src/attacks.py:SEED` 相同的测试 seed；只为生成可复现的测试密钥。
pub const D1E_TEST_SEED: &[u8] = b"EXP-D1-E-fixed-seed-v1";

#[derive(Clone, Debug)]
pub struct Witness {
    pub id: String,
    signing_key: SigningKey,
}

/// 仅测试用签名器；不得作为验证器输入。
#[derive(Clone)]
pub struct TestQuorumSigner {
    pub witnesses: Vec<Witness>,
    pub publics: Vec<(String, VerifyingKey)>,
    pub threshold: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub checkpoint_hash: Hash32,
    pub epoch: u64,
    pub previous_hash: Hash32,
    pub signatures: Vec<(String, [u8; 64])>,
}

impl QuorumCertificate {
    /// 不同 witness ID 的数量，用于 trace 中给出可读的失败细节。
    pub fn distinct_signer_count(&self) -> usize {
        let mut ids: Vec<&str> = self.signatures.iter().map(|(id, _)| id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }
}

fn test_derive_key(id: &str) -> SigningKey {
    let mut h = Sha256::new();
    h.update(D1E_TEST_SEED);
    h.update(b"|");
    h.update(id.as_bytes());
    let key_bytes: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&key_bytes)
}

impl TestQuorumSigner {
    /// 只创建测试密钥：公开 seed + witness id。生产验证不使用此函数。
    pub fn new_test_signer() -> Self {
        let mut witnesses = Vec::new();
        let mut publics = Vec::new();
        for i in 1..=WITNESS_COUNT {
            let id = format!("W{}", i);
            let signing_key = test_derive_key(&id);
            let verifying_key = signing_key.verifying_key();
            publics.push((id.clone(), verifying_key));
            witnesses.push(Witness { id, signing_key });
        }
        Self {
            witnesses,
            publics,
            threshold: THRESHOLD,
        }
    }

    /// 按 D1-E 规则，前 threshold 个见证者对完整 checkpoint 编码签名。
    pub fn make_qc(&self, cp: &Checkpoint) -> QuorumCertificate {
        let data = encode_d1e_checkpoint(cp);
        let mut signatures = Vec::new();
        for w in self.witnesses.iter().take(self.threshold) {
            let sig: Signature = w.signing_key.sign(&data);
            signatures.push((w.id.clone(), sig.to_bytes()));
        }
        QuorumCertificate {
            checkpoint_hash: checkpoint_hash(cp),
            epoch: cp.epoch,
            previous_hash: cp.previous_hash,
            signatures,
        }
    }
}
