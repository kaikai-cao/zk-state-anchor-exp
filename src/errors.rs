//! 验证器失败原因：不用统一 false，拒绝必须带可区分的枚举原因。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    InvalidAnchorDigest,
    PublicInputMismatch,
    InvalidLogInclusion,
    InvalidQuorumCertificate,
    CheckpointRollback,
    CheckpointGap,
    InvalidPredecessor,
    PolicyVersionMismatch,
    FreshnessUnavailable,
    // 以下两项为任务包九类之外的细分原因，便于区分“锚点字段错误”与“checkpoint 错误”。
    AnchorEpochMismatch,
    AnchorRecordMismatch,
}

impl FailureReason {
    pub fn code(&self) -> &'static str {
        match self {
            FailureReason::InvalidAnchorDigest => "INVALID_ANCHOR_DIGEST",
            FailureReason::PublicInputMismatch => "PUBLIC_INPUT_MISMATCH",
            FailureReason::InvalidLogInclusion => "INVALID_LOG_INCLUSION",
            FailureReason::InvalidQuorumCertificate => "INVALID_QUORUM_CERTIFICATE",
            FailureReason::CheckpointRollback => "CHECKPOINT_ROLLBACK",
            FailureReason::CheckpointGap => "CHECKPOINT_GAP",
            FailureReason::InvalidPredecessor => "INVALID_PREDECESSOR",
            FailureReason::PolicyVersionMismatch => "POLICY_VERSION_MISMATCH",
            FailureReason::FreshnessUnavailable => "FRESHNESS_UNAVAILABLE",
            FailureReason::AnchorEpochMismatch => "ANCHOR_EPOCH_MISMATCH",
            FailureReason::AnchorRecordMismatch => "ANCHOR_RECORD_MISMATCH",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    pub accepted: bool,
    pub reason: Option<FailureReason>,
    pub trace: Vec<String>,
}

impl VerifyResult {
    pub fn accept(trace: Vec<String>) -> Self {
        Self { accepted: true, reason: None, trace }
    }

    pub fn reject(reason: FailureReason, trace: Vec<String>) -> Self {
        Self { accepted: false, reason: Some(reason), trace }
    }
}
