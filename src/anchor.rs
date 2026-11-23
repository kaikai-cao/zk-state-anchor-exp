//! AuthzStateAnchor：把 D2-A 的 Poseidon GR/RR 与外部 D1-E 状态链连接的数据结构和摘要。

use crate::encoding::{bytes_with_len, domain, sha256, str_with_len, u32be, u64be, FieldBytes, Hash32};

pub const PROTOCOL_VERSION: u32 = 1;

/// A_e = H(D_A || version || epoch || policyVersion || GR || RR || A_{e-1})
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzStateAnchor {
    pub version: u32,
    pub epoch: u64,
    pub policy_version: u32,
    pub grant_root: FieldBytes,
    pub revoke_root: FieldBytes,
    pub prev_anchor_digest: Hash32,
}

impl AuthzStateAnchor {
    /// 数据结构确定性编码（用于 AnchorRecord，不用于摘要本身）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = domain("AuthzStateAnchor");
        out.extend_from_slice(&str_with_len("version"));
        out.extend_from_slice(&u32be(self.version));
        out.extend_from_slice(&str_with_len("epoch"));
        out.extend_from_slice(&u64be(self.epoch));
        out.extend_from_slice(&str_with_len("policy_version"));
        out.extend_from_slice(&u32be(self.policy_version));
        out.extend_from_slice(&str_with_len("grant_root"));
        out.extend_from_slice(&bytes_with_len(&self.grant_root.0));
        out.extend_from_slice(&str_with_len("revoke_root"));
        out.extend_from_slice(&bytes_with_len(&self.revoke_root.0));
        out.extend_from_slice(&str_with_len("prev_anchor_digest"));
        out.extend_from_slice(&bytes_with_len(&self.prev_anchor_digest.0));
        out
    }

    pub fn digest(&self) -> Hash32 {
        let mut out = domain("D_A");
        out.extend_from_slice(&u32be(self.version));
        out.extend_from_slice(&u64be(self.epoch));
        out.extend_from_slice(&u32be(self.policy_version));
        out.extend_from_slice(&bytes_with_len(&self.grant_root.0));
        out.extend_from_slice(&bytes_with_len(&self.revoke_root.0));
        out.extend_from_slice(&bytes_with_len(&self.prev_anchor_digest.0));
        sha256(&[&out])
    }
}

/// AnchorRecord_e = Encode(A_e, GR, RR, epoch, policyVersion, A_e digest)
/// 日志叶子 Leaf_e = SHA256(D_L || AnchorRecord_e)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    pub anchor: AuthzStateAnchor,
    pub anchor_digest: Hash32,
}

impl AnchorRecord {
    pub fn new(anchor: AuthzStateAnchor) -> Self {
        let anchor_digest = anchor.digest();
        Self { anchor, anchor_digest }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = domain("AnchorRecord");
        out.extend_from_slice(&str_with_len("anchor"));
        out.extend_from_slice(&bytes_with_len(&self.anchor.encode()));
        out.extend_from_slice(&str_with_len("anchor_digest"));
        out.extend_from_slice(&bytes_with_len(&self.anchor_digest.0));
        out
    }

    pub fn leaf_bytes(&self) -> Vec<u8> {
        let mut out = domain("D_L");
        out.extend_from_slice(&bytes_with_len(&self.encode()));
        out
    }

    pub fn self_consistent(&self) -> bool {
        self.anchor.digest() == self.anchor_digest
    }
}

/// 与 D2-A 电路 public inputs 的适配接口。本轮只绑定字段字节，不修改 D2-A。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Halo2AuthorizationPublicInputs {
    pub grant_root: FieldBytes,
    pub revoke_root: FieldBytes,
    pub request_digest: FieldBytes,
}
