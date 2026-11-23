//! T01–T20 场景构造器。测试与证据导出共用同一套构造器，避免两套实现漂移。

use crate::anchor::{
    AnchorRecord, AuthzStateAnchor, Halo2AuthorizationPublicInputs, PROTOCOL_VERSION,
};
use crate::checkpoint::{Checkpoint, CHAIN_ID};
use crate::encoding::{FieldBytes, Hash32};
use crate::errors::FailureReason;
use crate::freshness::{
    FreshnessProvider, HonestFreshnessProvider, StaleFreshnessProvider,
    UnavailableFreshnessProvider,
};
use crate::log::{InclusionProof, MerkleLog};
use crate::quorum::{QuorumCertificate, TestQuorumSigner, THRESHOLD};
use crate::verifier::{ClientState, ExpectedState, VerifyRequest};
use crate::witness_set::TrustedWitnessSet;

const LOG_ID: &str = "authz-log-1";

pub struct Scenario {
    pub id: &'static str,
    pub title: &'static str,
    pub expected_reason: Option<FailureReason>,
    pub expected_accepted: bool,
    pub request: VerifyRequest,
}

struct CaseParts {
    anchor: AuthzStateAnchor,
    record: AnchorRecord,
    log: MerkleLog,
    inclusion: InclusionProof,
    checkpoint: Checkpoint,
    qc: QuorumCertificate,
    halo2: Halo2AuthorizationPublicInputs,
    expected: ExpectedState,
    client: ClientState,
    signer: TestQuorumSigner,
    trusted_witness_set: TrustedWitnessSet,
}

impl CaseParts {
    fn base() -> Self {
        let signer = TestQuorumSigner::new_test_signer();
        let trusted_witness_set =
            TrustedWitnessSet::from_verifying_keys(&signer.publics, THRESHOLD);
        let prev_anchor = Hash32::from_label("anchor-epoch-7");
        let grant_root = FieldBytes::from_u64(1001);
        let revoke_root = FieldBytes::from_u64(1002);
        let anchor = AuthzStateAnchor {
            version: PROTOCOL_VERSION,
            epoch: 8,
            policy_version: 1,
            grant_root,
            revoke_root,
            prev_anchor_digest: prev_anchor,
        };
        let record = AnchorRecord::new(anchor.clone());

        let mut log = MerkleLog::new(LOG_ID);
        log.append(b"prior unrelated log entry".to_vec());
        let index = log.append(record.leaf_bytes());
        log.append(b"later unrelated log entry".to_vec());
        let inclusion = log.inclusion_proof(index).expect("anchor leaf index");

        let checkpoint = Checkpoint {
            chain_id: CHAIN_ID.to_string(),
            epoch: 8,
            previous_hash: Hash32::from_label("checkpoint-epoch-7"),
            state_root: Hash32::from_label("d1e-state-root-8"),
            log_root: Hash32(log.root()),
            policy_version: "1".to_string(),
            witness_set_root: trusted_witness_set.compute_root(),
            log_size: log.size() as u64,
            timestamp: 1000,
        };
        let qc = signer.make_qc(&checkpoint);
        let halo2 = Halo2AuthorizationPublicInputs {
            grant_root,
            revoke_root,
            request_digest: FieldBytes::from_u64(20_261_123),
        };
        let expected = ExpectedState {
            chain_id: CHAIN_ID.to_string(),
            log_id: LOG_ID.to_string(),
            policy_version: 1,
            epoch: 8,
            trusted_prev_anchor_digest: prev_anchor,
        };
        let client = ClientState {
            known_epoch: Some(7),
            known_checkpoint_hash: Some(checkpoint.previous_hash),
        };
        Self {
            anchor,
            record,
            log,
            inclusion,
            checkpoint,
            qc,
            halo2,
            expected,
            client,
            signer,
            trusted_witness_set,
        }
    }

    /// 修改 anchor 后重新计算摘要、重建日志叶子与 checkpoint/QC，
    /// 使攻击可以越过前置检查，精确命中目标约束。
    fn change_anchor<F: FnOnce(&mut AuthzStateAnchor)>(&mut self, f: F) {
        f(&mut self.anchor);
        self.record.anchor = self.anchor.clone();
        self.record.anchor_digest = self.anchor.digest();
        self.refresh_log();
    }

    fn refresh_log(&mut self) {
        self.log.leaves[self.inclusion.index] = self.record.leaf_bytes();
        self.inclusion = self
            .log
            .inclusion_proof(self.inclusion.index)
            .expect("refreshed proof");
        self.checkpoint.log_root = Hash32(self.log.root());
        self.checkpoint.log_size = self.log.size() as u64;
        self.qc = self.signer.make_qc(&self.checkpoint);
    }

    fn refresh_qc(&mut self) {
        self.qc = self.signer.make_qc(&self.checkpoint);
    }

    fn into_request(self, freshness: Box<dyn FreshnessProvider>) -> VerifyRequest {
        VerifyRequest {
            anchor: self.anchor,
            record: self.record,
            inclusion: self.inclusion,
            checkpoint: self.checkpoint,
            qc: self.qc,
            halo2: self.halo2,
            expected: self.expected,
            client: self.client,
            freshness,
            trusted_witness_set: self.trusted_witness_set,
        }
    }

    fn into_honest_request(self) -> VerifyRequest {
        let freshness = Box::new(HonestFreshnessProvider::for_checkpoint(&self.checkpoint));
        self.into_request(freshness)
    }

    fn into_stale_request(self) -> VerifyRequest {
        let stale = StaleFreshnessProvider::from_values(7, Hash32::from_label("old-checkpoint-7"));
        self.into_request(Box::new(stale))
    }

    fn into_unavailable_request(self) -> VerifyRequest {
        self.into_request(Box::new(UnavailableFreshnessProvider))
    }
}

fn scenario(
    id: &'static str,
    title: &'static str,
    expected_reason: Option<FailureReason>,
    request: VerifyRequest,
) -> Scenario {
    Scenario {
        id,
        title,
        expected_reason,
        expected_accepted: expected_reason.is_none(),
        request,
    }
}

pub fn all_scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();

    // T01 正常路径
    out.push(scenario(
        "T01",
        "正常 anchor + 有效 QC + inclusion",
        None,
        CaseParts::base().into_honest_request(),
    ));

    // T02/T03 修改 GR/RR 并重新计算摘要：应命中 public input 绑定
    let mut c = CaseParts::base();
    c.change_anchor(|a| a.grant_root = FieldBytes::from_u64(2002));
    out.push(scenario(
        "T02",
        "修改 grant_root",
        Some(FailureReason::PublicInputMismatch),
        c.into_honest_request(),
    ));

    let mut c = CaseParts::base();
    c.change_anchor(|a| a.revoke_root = FieldBytes::from_u64(2003));
    out.push(scenario(
        "T03",
        "修改 revoke_root",
        Some(FailureReason::PublicInputMismatch),
        c.into_honest_request(),
    ));

    // T04 修改 epoch：锚点与 checkpoint 的 epoch 不一致
    let mut c = CaseParts::base();
    c.change_anchor(|a| a.epoch = 7);
    out.push(scenario(
        "T04",
        "修改 epoch",
        Some(FailureReason::AnchorEpochMismatch),
        c.into_honest_request(),
    ));

    // T05 修改 policy_version：策略版本绑定失败
    let mut c = CaseParts::base();
    c.change_anchor(|a| a.policy_version = 0);
    out.push(scenario(
        "T05",
        "修改 policy_version",
        Some(FailureReason::PolicyVersionMismatch),
        c.into_honest_request(),
    ));

    // T06 修改 prev_anchor_digest：前驱关系失败
    let mut c = CaseParts::base();
    c.change_anchor(|a| a.prev_anchor_digest = Hash32::from_label("forged-predecessor"));
    out.push(scenario(
        "T06",
        "修改 prev_anchor_digest",
        Some(FailureReason::InvalidPredecessor),
        c.into_honest_request(),
    ));

    // T07 伪造 anchor_digest（只改 digest，不改摘要输入）
    let mut c = CaseParts::base();
    c.record.anchor_digest = Hash32::from_label("forged-digest");
    out.push(scenario(
        "T07",
        "伪造 anchor_digest",
        Some(FailureReason::InvalidAnchorDigest),
        c.into_honest_request(),
    ));

    // T08 inclusion proof 被篡改
    let mut c = CaseParts::base();
    c.inclusion.siblings[0][0] ^= 0x01;
    out.push(scenario(
        "T08",
        "日志 inclusion proof 错误",
        Some(FailureReason::InvalidLogInclusion),
        c.into_honest_request(),
    ));

    // T09 使用其他日志的 proof（log_id 与内容都不匹配）
    let mut c = CaseParts::base();
    let mut other = MerkleLog::new("other-log");
    other.append(b"other prior".to_vec());
    let other_index = other.append(c.record.leaf_bytes());
    other.append(b"other later".to_vec());
    c.inclusion = other.inclusion_proof(other_index).expect("other log proof");
    out.push(scenario(
        "T09",
        "使用其他日志的 inclusion proof",
        Some(FailureReason::InvalidLogInclusion),
        c.into_honest_request(),
    ));

    // T10 QC 签名无效
    let mut c = CaseParts::base();
    c.qc.signatures[0].1[0] ^= 0x01;
    out.push(scenario(
        "T10",
        "QC 签名无效",
        Some(FailureReason::InvalidQuorumCertificate),
        c.into_honest_request(),
    ));

    // T11 QC quorum 不足
    let mut c = CaseParts::base();
    c.qc.signatures.truncate(2);
    out.push(scenario(
        "T11",
        "QC quorum 不足",
        Some(FailureReason::InvalidQuorumCertificate),
        c.into_honest_request(),
    ));

    // T12 checkpoint 前驱哈希不匹配（QC 对该 checkpoint 仍有效）
    let mut c = CaseParts::base();
    c.checkpoint.previous_hash = Hash32::from_label("wrong-parent");
    c.refresh_qc();
    out.push(scenario(
        "T12",
        "checkpoint 前驱哈希不匹配",
        Some(FailureReason::CheckpointGap),
        c.into_honest_request(),
    ));

    // T13 checkpoint epoch 倒退（QC 对倒退 checkpoint 有效）
    let mut c = CaseParts::base();
    c.checkpoint.epoch = 7;
    c.refresh_qc();
    out.push(scenario(
        "T13",
        "checkpoint epoch 倒退",
        Some(FailureReason::AnchorEpochMismatch),
        c.into_honest_request(),
    ));

    // T14 客户端已认可 epoch 9，尝试回滚到 epoch 8
    let mut c = CaseParts::base();
    c.client.known_epoch = Some(9);
    c.client.known_checkpoint_hash = Some(Hash32::from_label("checkpoint-epoch-9"));
    out.push(scenario(
        "T14",
        "客户端已见更新 checkpoint，尝试回滚",
        Some(FailureReason::CheckpointRollback),
        c.into_honest_request(),
    ));

    // T15/T16/T17 freshness 三种情况（冷启动）
    let mut c = CaseParts::base();
    c.client = ClientState::default();
    out.push(scenario(
        "T15",
        "冷启动 + freshness 返回最新",
        None,
        c.into_honest_request(),
    ));

    let mut c = CaseParts::base();
    c.client = ClientState::default();
    out.push(scenario(
        "T16",
        "冷启动 + freshness 返回旧 checkpoint",
        Some(FailureReason::FreshnessUnavailable),
        c.into_stale_request(),
    ));

    let mut c = CaseParts::base();
    c.client = ClientState::default();
    out.push(scenario(
        "T17",
        "freshness provider 不可用",
        Some(FailureReason::FreshnessUnavailable),
        c.into_unavailable_request(),
    ));

    // T18 Halo2 public inputs 与 anchor 不一致
    let mut c = CaseParts::base();
    c.halo2.grant_root = FieldBytes::from_u64(9999);
    out.push(scenario(
        "T18",
        "Halo2 public inputs 与 anchor 不一致",
        Some(FailureReason::PublicInputMismatch),
        c.into_honest_request(),
    ));

    // T19 旧 policy version
    let mut c = CaseParts::base();
    c.change_anchor(|a| a.policy_version = 0);
    c.expected.policy_version = 2;
    out.push(scenario(
        "T19",
        "旧 policy version",
        Some(FailureReason::PolicyVersionMismatch),
        c.into_honest_request(),
    ));

    // T20 修改日志中的 AnchorRecord 内容（叶子改变但 checkpoint 根不变）
    let mut c = CaseParts::base();
    c.log.leaves[c.inclusion.index] = b"tampered anchor record".to_vec();
    c.inclusion = c
        .log
        .inclusion_proof(c.inclusion.index)
        .expect("tampered proof");
    out.push(scenario(
        "T20",
        "修改日志中的 AnchorRecord 内容",
        Some(FailureReason::InvalidLogInclusion),
        c.into_honest_request(),
    ));

    out
}

pub fn by_id(id: &str) -> Scenario {
    all_scenarios()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("unknown scenario {id}"))
}
