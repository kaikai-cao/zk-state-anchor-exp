//! 4 见证者 3-of-4 QC adapter，签名内容为 D1-E 完整 checkpoint 编码。
//!
//! 核查来源：D1-E `src/quorum.py:45-98`（verify_qc 检查 checkpoint_hash、epoch、
//! previous_hash、3 个不同 witness_id 及 Ed25519 验签）与 `src/crypto.py:50-60`
//! （Ed25519 私钥由 sha256(seed|key_id) 确定性派生）。本轮不实现签名锁定表，
//! 因为 D2-B 只验证 QC，不重新执行见证者签名行为；这是显式边界。

use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::checkpoint::{checkpoint_hash, encode_d1e_checkpoint, Checkpoint};
use crate::encoding::Hash32;

pub const THRESHOLD: usize = 3;
pub const WITNESS_COUNT: usize = 4;

#[derive(Clone, Debug)]
pub struct Witness {
    pub id: String,
    signing_key: SigningKey,
}

#[derive(Clone)]
pub struct QuorumSigner {
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

fn derive_key(id: &str) -> SigningKey {
    let seed = b"EXP-D2-B-01-WITNESS-SEED";
    let mut h = Sha256::new();
    h.update(seed);
    h.update(b"|");
    h.update(id.as_bytes());
    let key_bytes: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&key_bytes)
}

impl QuorumSigner {
    pub fn new() -> Arc<Self> {
        let mut witnesses = Vec::new();
        let mut publics = Vec::new();
        for i in 1..=WITNESS_COUNT {
            let id = format!("W{}", i);
            let signing_key = derive_key(&id);
            let verifying_key = signing_key.verifying_key();
            publics.push((id.clone(), verifying_key));
            witnesses.push(Witness { id, signing_key });
        }
        Arc::new(Self { witnesses, publics, threshold: THRESHOLD })
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

    /// 返回 Err 即验证失败；不把所有失败压成 bool。
    pub fn verify_qc(&self, qc: &QuorumCertificate, cp: &Checkpoint) -> Result<(), String> {
        if qc.checkpoint_hash != checkpoint_hash(cp) {
            return Err("checkpoint_hash mismatch".to_string());
        }
        if qc.epoch != cp.epoch || qc.previous_hash != cp.previous_hash {
            return Err("qc epoch/previous_hash mismatch".to_string());
        }
        let data = encode_d1e_checkpoint(cp);
        let mut distinct: Vec<(&String, &[u8; 64])> = Vec::new();
        for (id, sig) in &qc.signatures {
            if let Some((_, old)) = distinct.iter().find(|(d, _)| *d == id) {
                if *old != sig {
                    return Err("duplicate witness id with different signature".to_string());
                }
                continue;
            }
            distinct.push((id, sig));
        }
        if distinct.len() < self.threshold {
            return Err(format!("only {} distinct signatures, need {}", distinct.len(), self.threshold));
        }
        for (id, sig_bytes) in distinct {
            let vk = self
                .publics
                .iter()
                .find(|(k, _)| k == id)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("unknown witness {}", id))?;
            let sig = Signature::from_bytes(sig_bytes);
            if vk.verify(&data, &sig).is_err() {
                return Err(format!("invalid signature from {}", id));
            }
        }
        Ok(())
    }
}
