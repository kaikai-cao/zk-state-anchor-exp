//! EXP-D2-B-R1 / F01–F06：结构化 freshness 判定攻击矩阵。
//!
//! 判定只来自 provider 返回的 TrustedCheckpoint 结构；trace 文本不参与 ACCEPT 决策。

use zk_state_anchor_exp::checkpoint::{checkpoint_hash, Checkpoint};
use zk_state_anchor_exp::encoding::Hash32;
use zk_state_anchor_exp::errors::VerifyResult;
use zk_state_anchor_exp::freshness::{FreshnessError, FreshnessProvider, TrustedCheckpoint};
use zk_state_anchor_exp::scenarios::by_id;
use zk_state_anchor_exp::verifier::{verify_authz_state_anchor, VerifyRequest};

struct FixedProvider {
    label: &'static str,
    result: Result<TrustedCheckpoint, FreshnessError>,
}

impl FreshnessProvider for FixedProvider {
    fn label(&self) -> &'static str {
        self.label
    }

    fn get_latest_checkpoint(&self) -> Result<TrustedCheckpoint, FreshnessError> {
        self.result.clone()
    }
}

fn base_request() -> VerifyRequest {
    by_id("T01").request
}

fn run_with<F>(make: F) -> VerifyResult
where
    F: FnOnce(&Checkpoint) -> Box<dyn FreshnessProvider>,
{
    let mut req = base_request();
    let provider = make(&req.checkpoint);
    req.freshness = provider;
    verify_authz_state_anchor(&req)
}

fn fixed(
    label: &'static str,
    epoch: u64,
    checkpoint_hash_value: Hash32,
) -> Box<dyn FreshnessProvider> {
    Box::new(FixedProvider {
        label,
        result: Ok(TrustedCheckpoint {
            epoch,
            checkpoint_hash: checkpoint_hash_value,
        }),
    })
}

fn assert_freshness_reject(result: &VerifyResult, detail: &str) {
    assert!(!result.accepted);
    assert_eq!(
        result.reason.expect("reject reason").code(),
        "FRESHNESS_UNAVAILABLE"
    );
    assert!(
        result
            .trace
            .iter()
            .any(|s| s.contains("[9/10] freshness") && s.contains(detail)),
        "missing freshness trace detail {detail}:\n{}",
        result.trace.join("\n")
    );
}

#[test]
fn f01_correct_epoch_and_hash_accepts() {
    let result = run_with(|cp| fixed("F01Provider", cp.epoch, checkpoint_hash(cp)));
    assert!(result.accepted);
    assert_eq!(result.reason, None);
    assert!(result.trace.iter().any(|s| s.contains("[9/10] freshness")
        && s.contains("epoch_match=true")
        && s.contains("hash_match=true")
        && s.contains("match=true")));
}

#[test]
fn f02_stale_epoch_and_old_hash_rejected() {
    let result = run_with(|_| fixed("F02Provider", 5, Hash32::from_label("old-epoch-hash")));
    assert_freshness_reject(&result, "epoch_match=false");
    assert_freshness_reject(&result, "hash_match=false");
}

#[test]
fn f03_correct_epoch_wrong_hash_rejected() {
    let result = run_with(|cp| fixed("F03Provider", cp.epoch, Hash32::from_label("wrong-hash")));
    assert_freshness_reject(&result, "epoch_match=true");
    assert_freshness_reject(&result, "hash_match=false");
}

#[test]
fn f04_wrong_epoch_correct_hash_rejected() {
    let result = run_with(|cp| fixed("F04Provider", cp.epoch - 1, checkpoint_hash(cp)));
    assert_freshness_reject(&result, "epoch_match=false");
    assert_freshness_reject(&result, "hash_match=true");
}

#[test]
fn f05_provider_unavailable_rejected() {
    let result = run_with(|_| {
        Box::new(FixedProvider {
            label: "F05Provider",
            result: Err(FreshnessError::Unavailable),
        })
    });
    assert_freshness_reject(&result, "error=Unavailable");
    assert_freshness_reject(&result, "match=false");
}

#[test]
fn f06_decision_ignores_trace_text() {
    // 正确结构 + 标签里写着 match=false：必须 ACCEPT。
    let accept = run_with(|cp| {
        fixed(
            "F06Provider-pretend-match=false",
            cp.epoch,
            checkpoint_hash(cp),
        )
    });
    assert!(accept.accepted);
    assert!(accept
        .trace
        .iter()
        .any(|s| s.contains("F06Provider-pretend-match=false") && s.contains("match=true")));

    // 旧结构 + 标签伪装成 HonestFreshnessProvider：必须 REJECT。
    let reject = run_with(|_| fixed("HonestFreshnessProvider", 3, Hash32::from_label("stale-3")));
    assert_freshness_reject(&reject, "epoch_match=false");
}
