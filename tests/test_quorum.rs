mod common;

use common::{check, reason_code};

#[test]
fn t10_invalid_qc_signature_rejected() {
    let r = check("T10");
    assert_eq!(reason_code(&r), "INVALID_QUORUM_CERTIFICATE");
    assert!(r.trace.iter().any(|s| s.contains("invalid signature from")));
}

#[test]
fn t11_insufficient_quorum_rejected() {
    let r = check("T11");
    assert_eq!(reason_code(&r), "INVALID_QUORUM_CERTIFICATE");
    assert!(r
        .trace
        .iter()
        .any(|s| s.contains("only 2 distinct signatures")));
}

#[test]
fn t12_checkpoint_parent_mismatch_rejected() {
    let r = check("T12");
    assert_eq!(reason_code(&r), "CHECKPOINT_GAP");
}
