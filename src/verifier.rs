//! 外部验证器：把 Halo2 public inputs、AuthzStateAnchor、日志 inclusion proof、
//! D1-E checkpoint/QC、客户端本地状态和 freshness provider 组合起来验证。
//!
//! 验证成功只表示：
//! 1. anchor 摘要自洽且绑定了与 Halo2 相同的 GR/RR；
//! 2. AnchorRecord 在 QC 认证的 log_root 对应日志中；
//! 3. checkpoint 与客户端已知状态连续、不回滚；
//! 4. freshness provider 对 presented checkpoint 给出了匹配的可信 attestation。
//!
//! 它不证明 GR/RR 与 D1-E state_root 对应的事件历史在语义上一致；该缺口见 docs/protocol.md。

use crate::anchor::{AnchorRecord, Halo2AuthorizationPublicInputs};
use crate::checkpoint::{checkpoint_hash, Checkpoint};
use crate::errors::{FailureReason, VerifyResult};
use crate::freshness::FreshnessProvider;
use crate::log::InclusionProof;
use crate::quorum::QuorumCertificate;
use crate::witness_set::{QcError, TrustedWitnessSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedState {
    pub chain_id: String,
    pub log_id: String,
    pub policy_version: u32,
    pub epoch: u64,
    pub trusted_prev_anchor_digest: crate::encoding::Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ClientState {
    /// None 表示冷启动客户端：本地没有已认可 checkpoint 历史。
    pub known_epoch: Option<u64>,
    pub known_checkpoint_hash: Option<crate::encoding::Hash32>,
}

pub struct VerifyRequest {
    pub anchor: crate::anchor::AuthzStateAnchor,
    pub record: AnchorRecord,
    pub inclusion: InclusionProof,
    pub checkpoint: Checkpoint,
    pub qc: QuorumCertificate,
    pub halo2: Halo2AuthorizationPublicInputs,
    pub expected: ExpectedState,
    pub client: ClientState,
    pub freshness: Box<dyn FreshnessProvider>,
    /// 带外显式可信集合。生产路径必须由 `TrustedWitnessSet::from_trusted_config`
    /// 用调用方提供的 expected_root 构造；验证器不持有签名私钥，也不从公开 seed 派生密钥。
    pub trusted_witness_set: TrustedWitnessSet,
}

fn step(trace: &mut Vec<String>, n: usize, name: &str, detail: &str, ok: bool) {
    let mark = if ok { "OK" } else { "FAIL" };
    trace.push(format!("[{}/10] {} | {} | {}", n, name, mark, detail));
}

fn done(mut trace: Vec<String>, reason: Option<FailureReason>) -> VerifyResult {
    match reason {
        None => {
            trace.push("VERDICT: ACCEPT".to_string());
            VerifyResult::accept(trace)
        }
        Some(r) => {
            trace.push(format!("VERDICT: REJECT {}", r.code()));
            VerifyResult::reject(r, trace)
        }
    }
}

/// 把细分 QC 错误码映射为可读 trace 细节；码本身仍以 `code=` 前缀保留。
fn qc_detail(err: QcError, req: &VerifyRequest) -> String {
    let code = err.code();
    let human = match err {
        QcError::InsufficientSignatures => format!(
            "only {} distinct signatures, need {}",
            req.qc.distinct_signer_count(),
            req.trusted_witness_set.threshold
        ),
        QcError::InvalidSignature => "invalid signature from trusted witness".to_string(),
        QcError::InvalidWitnessSetConfig(_) => "invalid witness set configuration".to_string(),
        _ => code.to_string(),
    };
    format!("{} {}", code, human)
}

pub fn verify_authz_state_anchor(req: &VerifyRequest) -> VerifyResult {
    let mut trace = Vec::new();

    // 1. AnchorRecord 编码一致性与 anchor digest
    let record_ok = req.record.anchor == req.anchor;
    step(
        &mut trace,
        1,
        "anchor_record",
        "record.anchor == request.anchor",
        record_ok,
    );
    if !record_ok {
        return done(trace, Some(FailureReason::AnchorRecordMismatch));
    }
    let recomputed = req.anchor.digest();
    let digest_ok = recomputed == req.record.anchor_digest && req.record.self_consistent();
    step(
        &mut trace,
        1,
        "anchor_digest",
        &format!(
            "computed={} provided={}",
            recomputed.to_hex(),
            req.record.anchor_digest.to_hex()
        ),
        digest_ok,
    );
    if !digest_ok {
        return done(trace, Some(FailureReason::InvalidAnchorDigest));
    }

    // 2. Halo2 public inputs 与 anchor 的 GR/RR 字节一致
    let fields_ok = req.halo2.grant_root.is_canonical()
        && req.halo2.revoke_root.is_canonical()
        && req.anchor.grant_root.is_canonical()
        && req.anchor.revoke_root.is_canonical();
    let pi_ok = fields_ok
        && req.halo2.grant_root == req.anchor.grant_root
        && req.halo2.revoke_root == req.anchor.revoke_root;
    step(
        &mut trace,
        2,
        "public_inputs",
        &format!(
            "GR_h2={} GR_anchor={} RR_h2={} RR_anchor={}",
            req.halo2.grant_root.to_hex(),
            req.anchor.grant_root.to_hex(),
            req.halo2.revoke_root.to_hex(),
            req.anchor.revoke_root.to_hex()
        ),
        pi_ok,
    );
    if !pi_ok {
        return done(trace, Some(FailureReason::PublicInputMismatch));
    }

    // 3. epoch / policy version
    let epoch_ok =
        req.anchor.epoch == req.expected.epoch && req.anchor.epoch == req.checkpoint.epoch;
    step(
        &mut trace,
        3,
        "epoch_binding",
        &format!(
            "anchor={} checkpoint={} expected={}",
            req.anchor.epoch, req.checkpoint.epoch, req.expected.epoch
        ),
        epoch_ok,
    );
    if !epoch_ok {
        return done(trace, Some(FailureReason::AnchorEpochMismatch));
    }
    let policy_ok = req.anchor.policy_version == req.expected.policy_version
        && req.checkpoint.policy_version == req.anchor.policy_version.to_string();
    step(
        &mut trace,
        3,
        "policy_binding",
        &format!(
            "anchor={} checkpoint={} expected={}",
            req.anchor.policy_version, req.checkpoint.policy_version, req.expected.policy_version
        ),
        policy_ok,
    );
    if !policy_ok {
        return done(trace, Some(FailureReason::PolicyVersionMismatch));
    }

    // 4. 日志 inclusion proof（同时检查 log_id、记录字节、树大小与 checkpoint log_root）
    let inclusion_ok = req.inclusion.log_id == req.expected.log_id
        && req.inclusion.leaf == req.record.leaf_bytes()
        && req.inclusion.index < req.inclusion.tree_size
        && req.inclusion.tree_size as u64 == req.checkpoint.log_size
        && req.inclusion.verify(&req.checkpoint.log_root.0);
    step(
        &mut trace,
        4,
        "log_inclusion",
        &format!(
            "log_id={} index={} size={} cp_log_root={}",
            req.inclusion.log_id,
            req.inclusion.index,
            req.inclusion.tree_size,
            req.checkpoint.log_root.to_hex()
        ),
        inclusion_ok,
    );
    if !inclusion_ok {
        return done(trace, Some(FailureReason::InvalidLogInclusion));
    }

    // 5a. 可信见证者集合绑定：验签之前先核对集合根与 checkpoint 声明的根
    let binding = req.trusted_witness_set.check_binding(&req.checkpoint);
    let computed_root = req.trusted_witness_set.compute_root();
    step(
        &mut trace,
        5,
        "witness_set_binding",
        &format!(
            "computed_root={} expected_root={} checkpoint_root={} code={}",
            computed_root.to_hex(),
            req.trusted_witness_set.expected_root.to_hex(),
            req.checkpoint.witness_set_root.to_hex(),
            binding.as_ref().err().map(|e| e.code()).unwrap_or("OK")
        ),
        binding.is_ok(),
    );
    if let Err(e) = binding {
        step(
            &mut trace,
            5,
            "quorum_certificate",
            &format!(
                "signatures={} detail={}",
                req.qc.signatures.len(),
                qc_detail(e, req)
            ),
            false,
        );
        return done(trace, Some(FailureReason::InvalidQuorumCertificate));
    }

    // 5b. D1-E quorum certificate（显式可信集合下的 3-of-4 Ed25519 验签）
    let qc_result = req.trusted_witness_set.verify_qc(&req.qc, &req.checkpoint);
    let qc_ok = qc_result.is_ok();
    let qc_text = match qc_result {
        Ok(()) => "valid".to_string(),
        Err(e) => qc_detail(e, req),
    };
    step(
        &mut trace,
        5,
        "quorum_certificate",
        &format!("signatures={} detail={}", req.qc.signatures.len(), qc_text),
        qc_ok,
    );
    if !qc_ok {
        return done(trace, Some(FailureReason::InvalidQuorumCertificate));
    }

    // 6. checkpoint 自身字段与 inclusion proof 的一致性（state_root 不得被 log_root 替换）
    let cp_ok = req.checkpoint.chain_id == req.expected.chain_id
        && req.checkpoint.log_size as usize == req.inclusion.tree_size;
    step(
        &mut trace,
        6,
        "checkpoint_fields",
        &format!(
            "chain_id={} state_root={} log_root={} sizes_match={}",
            req.checkpoint.chain_id,
            req.checkpoint.state_root.to_hex(),
            req.checkpoint.log_root.to_hex(),
            req.checkpoint.log_size as usize == req.inclusion.tree_size
        ),
        cp_ok,
    );
    if !cp_ok {
        return done(trace, Some(FailureReason::CheckpointGap));
    }

    // 7. 客户端已知状态的连续性与单调性
    let mut continuity_ok = true;
    let mut continuity_detail = String::from("cold start: no local high-watermark");
    if let Some(known) = req.client.known_epoch {
        continuity_detail = format!(
            "known_epoch={} offered_epoch={}",
            known, req.checkpoint.epoch
        );
        if req.checkpoint.epoch <= known {
            continuity_ok = false;
        }
    }
    step(
        &mut trace,
        7,
        "no_rollback",
        &continuity_detail,
        continuity_ok,
    );
    if !continuity_ok {
        return done(trace, Some(FailureReason::CheckpointRollback));
    }
    let chain_ok = match req.client.known_checkpoint_hash {
        Some(expected_prev) => expected_prev == req.checkpoint.previous_hash,
        None => true,
    };
    step(
        &mut trace,
        7,
        "checkpoint_chain",
        &format!(
            "previous_hash={} known={}",
            req.checkpoint.previous_hash.to_hex(),
            req.client
                .known_checkpoint_hash
                .map(|h| h.to_hex())
                .unwrap_or_else(|| "none".to_string())
        ),
        chain_ok,
    );
    if !chain_ok {
        return done(trace, Some(FailureReason::CheckpointGap));
    }

    // 8. 锚点前驱关系
    let pred_ok = req.anchor.prev_anchor_digest == req.expected.trusted_prev_anchor_digest;
    step(
        &mut trace,
        8,
        "anchor_predecessor",
        &format!(
            "anchor_prev={} trusted_prev={}",
            req.anchor.prev_anchor_digest.to_hex(),
            req.expected.trusted_prev_anchor_digest.to_hex()
        ),
        pred_ok,
    );
    if !pred_ok {
        return done(trace, Some(FailureReason::InvalidPredecessor));
    }

    // 9. 外部 freshness：判定只依赖 provider 返回的结构化结果，与 trace 文本无关。
    //    epoch 与 checkpoint_hash 必须同时匹配；provider 不可用一律失败关闭。
    let offered_hash = checkpoint_hash(&req.checkpoint);
    let (freshness_ok, freshness_detail) = match req.freshness.get_latest_checkpoint() {
        Err(e) => (
            false,
            format!("{} error={:?} match=false", req.freshness.label(), e),
        ),
        Ok(latest) => {
            let epoch_ok = latest.epoch == req.checkpoint.epoch;
            let hash_ok = latest.checkpoint_hash == offered_hash;
            let ok = epoch_ok && hash_ok;
            (
                ok,
                format!(
                    "{} latest_epoch={} offered_epoch={} latest_hash={} offered_hash={} epoch_match={} hash_match={} match={}",
                    req.freshness.label(),
                    latest.epoch,
                    req.checkpoint.epoch,
                    latest.checkpoint_hash.to_hex(),
                    offered_hash.to_hex(),
                    epoch_ok,
                    hash_ok,
                    ok
                ),
            )
        }
    };
    step(&mut trace, 9, "freshness", &freshness_detail, freshness_ok);
    if !freshness_ok {
        return done(trace, Some(FailureReason::FreshnessUnavailable));
    }

    step(&mut trace, 10, "all_checks", "all nine checks passed", true);
    done(trace, None)
}
