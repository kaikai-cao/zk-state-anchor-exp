mod common;

use common::{check, reason_code};

#[test]
fn t01_normal_anchor_accepts() {
    let r = check("T01");
    assert_eq!(reason_code(&r), "ACCEPT");
    assert!(r
        .trace
        .iter()
        .any(|s| s.contains("[9/10] freshness") && s.contains("match=true")));
}

#[test]
fn t02_modified_grant_root_rejected() {
    let r = check("T02");
    assert_eq!(reason_code(&r), "PUBLIC_INPUT_MISMATCH");
    assert!(r
        .trace
        .iter()
        .any(|s| s.contains("GR_h2") && s.contains("GR_anchor")));
}

#[test]
fn t03_modified_revoke_root_rejected() {
    let r = check("T03");
    assert_eq!(reason_code(&r), "PUBLIC_INPUT_MISMATCH");
}

#[test]
fn t04_modified_epoch_rejected() {
    let r = check("T04");
    assert_eq!(reason_code(&r), "ANCHOR_EPOCH_MISMATCH");
}

#[test]
fn t05_modified_policy_version_rejected() {
    let r = check("T05");
    assert_eq!(reason_code(&r), "POLICY_VERSION_MISMATCH");
}

#[test]
fn t06_modified_predecessor_rejected() {
    let r = check("T06");
    assert_eq!(reason_code(&r), "INVALID_PREDECESSOR");
}

#[test]
fn t07_forged_anchor_digest_rejected() {
    let r = check("T07");
    assert_eq!(reason_code(&r), "INVALID_ANCHOR_DIGEST");
}

#[test]
fn t18_halo2_public_inputs_mismatch_rejected() {
    let r = check("T18");
    assert_eq!(reason_code(&r), "PUBLIC_INPUT_MISMATCH");
}

#[test]
fn t19_old_policy_version_rejected() {
    let r = check("T19");
    assert_eq!(reason_code(&r), "POLICY_VERSION_MISMATCH");
}
