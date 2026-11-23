//! EXP-D2-B-R2 / C01–C12：可信见证者集合配置有效性。
//!
//! 断言具体的 `WitnessSetConfigError` / `QcError` 类型或稳定错误码；
//! C10–C12 使用真实 `verify_authz_state_anchor` 接口。

use zk_state_anchor_exp::checkpoint::Checkpoint;
use zk_state_anchor_exp::encoding::Hash32;
use zk_state_anchor_exp::quorum::{TestQuorumSigner, THRESHOLD};
use zk_state_anchor_exp::scenarios::by_id;
use zk_state_anchor_exp::verifier::{verify_authz_state_anchor, VerifyRequest};
use zk_state_anchor_exp::witness_set::{QcError, TrustedWitnessSet, WitnessSetConfigError};

/// 来自 tests/vectors/witness_set_vectors.json，由 D1-E Python 函数生成。
const OUT_OF_BAND_ROOT: &str = "a76cf9ac0e6df916ba3bac18ce7a4e9e93b813b437a21cd35ae79a178905119d";

fn root() -> Hash32 {
    Hash32::from_hex(OUT_OF_BAND_ROOT).expect("out-of-band root")
}

fn signer() -> TestQuorumSigner {
    TestQuorumSigner::new_test_signer()
}

fn trusted() -> TrustedWitnessSet {
    TrustedWitnessSet::from_trusted_config(&signer().publics, THRESHOLD, root())
        .expect("valid 3-of-4 trusted config")
}

fn checkpoint_for(set: &TrustedWitnessSet) -> Checkpoint {
    Checkpoint {
        chain_id: "authz-chain-1".to_string(),
        epoch: 8,
        previous_hash: Hash32::from_label("config-test-prev"),
        state_root: Hash32::from_label("config-test-state"),
        log_root: Hash32::from_label("config-test-log"),
        policy_version: "1".to_string(),
        witness_set_root: set.compute_root(),
        log_size: 3,
        timestamp: 1000,
    }
}

fn honest_request(set: TrustedWitnessSet) -> VerifyRequest {
    let mut req = by_id("T01").request;
    req.trusted_witness_set = set;
    req
}

fn assert_reject_trace(result: &zk_state_anchor_exp::errors::VerifyResult, code: &str) {
    assert!(!result.accepted);
    assert_eq!(
        result.reason.expect("reject reason").code(),
        "INVALID_QUORUM_CERTIFICATE"
    );
    assert!(
        result.trace.iter().any(|s| s.contains(code)),
        "trace missing {code}:\n{}",
        result.trace.join("\n")
    );
}

// --- C01–C09：构造期配置校验 ---------------------------------------------------

#[test]
fn c01_correct_set_with_out_of_band_root_and_3_of_4_accepts() {
    let signer = signer();
    let set = trusted();
    let cp = checkpoint_for(&set);
    assert_eq!(set.compute_root(), root());
    assert_eq!(set.verify_qc(&signer.make_qc(&cp), &cp), Ok(()));
}

#[test]
fn c02_wrong_out_of_band_root_rejected() {
    let err = TrustedWitnessSet::from_trusted_config(
        &signer().publics,
        THRESHOLD,
        Hash32::from_label("wrong-out-of-band-root"),
    )
    .unwrap_err();
    assert_eq!(err, WitnessSetConfigError::WitnessSetRootMismatch);
    assert_eq!(err.code(), "WITNESS_SET_ROOT_MISMATCH");
}

#[test]
fn c03_zero_threshold_rejected() {
    let err = TrustedWitnessSet::from_trusted_config(&signer().publics, 0, root()).unwrap_err();
    assert_eq!(err, WitnessSetConfigError::ThresholdZero);
    assert_eq!(err.code(), "THRESHOLD_ZERO");
}

#[test]
fn c04_threshold_above_unique_keys_rejected() {
    let err = TrustedWitnessSet::from_trusted_config(&signer().publics, 5, root()).unwrap_err();
    assert_eq!(err, WitnessSetConfigError::ThresholdExceedsUniqueKeys);
    assert_eq!(err.code(), "THRESHOLD_EXCEEDS_UNIQUE_KEYS");
}

#[test]
fn c05_empty_witness_set_rejected() {
    let err = TrustedWitnessSet::from_trusted_config(
        &[],
        THRESHOLD,
        Hash32::from_label("empty-set-root"),
    )
    .unwrap_err();
    assert_eq!(err, WitnessSetConfigError::EmptyWitnessSet);
    assert_eq!(err.code(), "EMPTY_WITNESS_SET");
}

#[test]
fn c06_duplicate_witness_id_rejected() {
    let keys = signer().publics;
    let entries = vec![
        ("W1".to_string(), keys[0].1),
        ("W1".to_string(), keys[1].1),
        ("W3".to_string(), keys[2].1),
        ("W4".to_string(), keys[3].1),
    ];
    let err = TrustedWitnessSet::from_trusted_config(&entries, THRESHOLD, root()).unwrap_err();
    assert_eq!(err, WitnessSetConfigError::DuplicateWitnessId);
    assert_eq!(err.code(), "DUPLICATE_WITNESS_ID");
}

#[test]
fn c07_different_ids_sharing_one_public_key_rejected() {
    let keys = signer().publics;
    let entries = vec![
        ("W1".to_string(), keys[0].1),
        ("W2".to_string(), keys[0].1),
        ("W3".to_string(), keys[2].1),
        ("W4".to_string(), keys[3].1),
    ];
    let err = TrustedWitnessSet::from_trusted_config(&entries, THRESHOLD, root()).unwrap_err();
    assert_eq!(err, WitnessSetConfigError::DuplicatePublicKey);
    assert_eq!(err.code(), "DUPLICATE_PUBLIC_KEY");
}

#[test]
fn c08_valid_one_of_four_accepted() {
    let set = TrustedWitnessSet::from_trusted_config(&signer().publics, 1, root())
        .expect("1-of-4 is a legal config; default experiment parameter stays 3-of-4");
    assert_eq!(set.threshold, 1);
    assert_eq!(set.compute_root(), root());
}

#[test]
fn c09_valid_four_of_four_accepted() {
    let set = TrustedWitnessSet::from_trusted_config(&signer().publics, 4, root())
        .expect("4-of-4 is a legal config; default experiment parameter stays 3-of-4");
    assert_eq!(set.threshold, 4);
    assert_eq!(set.compute_root(), root());
}

// --- C10–C12：真实验证器接口 ---------------------------------------------------

#[test]
fn c10_valid_3_of_4_normal_qc_accepted_by_verifier() {
    let req = honest_request(trusted());
    let result = verify_authz_state_anchor(&req);
    assert!(result.accepted, "{}", result.trace.join("\n"));
    assert_eq!(result.reason, None);
    assert!(result
        .trace
        .iter()
        .any(|s| s.contains("witness_set_binding") && s.contains("code=OK")));
}

#[test]
fn c11_wrong_expected_root_cannot_enter_verifier() {
    let err = TrustedWitnessSet::from_trusted_config(
        &signer().publics,
        THRESHOLD,
        Hash32::from_label("attacker-controlled-root"),
    )
    .unwrap_err();
    assert_eq!(err, WitnessSetConfigError::WitnessSetRootMismatch);

    // 防御纵深：即使调用方绕过构造器直接篡改公开字段，验证器也必须拒绝。
    let mut req = honest_request(trusted());
    req.trusted_witness_set.expected_root = Hash32::from_label("attacker-controlled-root");
    let result = verify_authz_state_anchor(&req);
    assert_reject_trace(&result, "TRUSTED_SET_ROOT_MISMATCH");
}

#[test]
fn c12_illegal_config_cannot_pass_with_empty_signature_qc() {
    let err = TrustedWitnessSet::from_trusted_config(&signer().publics, 0, root()).unwrap_err();
    assert_eq!(err, WitnessSetConfigError::ThresholdZero);

    let mut req = honest_request(trusted());
    req.trusted_witness_set.threshold = 0;
    req.qc.signatures.clear();

    let direct = req
        .trusted_witness_set
        .verify_qc(&req.qc, &req.checkpoint)
        .unwrap_err();
    assert_eq!(
        direct,
        QcError::InvalidWitnessSetConfig(WitnessSetConfigError::ThresholdZero)
    );
    assert_eq!(direct.code(), "THRESHOLD_ZERO");

    let result = verify_authz_state_anchor(&req);
    assert_reject_trace(&result, "THRESHOLD_ZERO");
}
