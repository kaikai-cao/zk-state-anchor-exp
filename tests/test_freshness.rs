mod common;

use common::{check, reason_code};

#[test]
fn t14_client_high_watermark_rejects_rollback() {
    let r = check("T14");
    assert_eq!(reason_code(&r), "CHECKPOINT_ROLLBACK");
    assert!(r
        .trace
        .iter()
        .any(|s| s.contains("known_epoch=9 offered_epoch=8")));
}

#[test]
fn t15_cold_start_with_honest_freshness_accepts() {
    let r = check("T15");
    assert_eq!(reason_code(&r), "ACCEPT");
}

#[test]
fn t16_cold_start_with_stale_freshness_rejected() {
    let r = check("T16");
    assert_eq!(reason_code(&r), "FRESHNESS_UNAVAILABLE");
    assert!(r.trace.iter().any(|s| s.contains("match=false")));
}

#[test]
fn t17_freshness_unavailable_rejected() {
    let r = check("T17");
    assert_eq!(reason_code(&r), "FRESHNESS_UNAVAILABLE");
    assert!(r.trace.iter().any(
        |s| !s.contains("StaleFreshnessProvider") && s.contains("UnavailableFreshnessProvider")
    ));
}
