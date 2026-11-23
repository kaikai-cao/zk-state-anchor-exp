mod common;

use common::{check, reason_code};

#[test]
fn t08_tampered_inclusion_proof_rejected() {
    let r = check("T08");
    assert_eq!(reason_code(&r), "INVALID_LOG_INCLUSION");
}

#[test]
fn t09_other_log_proof_rejected() {
    let r = check("T09");
    assert_eq!(reason_code(&r), "INVALID_LOG_INCLUSION");
    assert!(r.trace.iter().any(|s| s.contains("log_id=other-log")));
}

#[test]
fn t20_modified_log_record_rejected() {
    let r = check("T20");
    assert_eq!(reason_code(&r), "INVALID_LOG_INCLUSION");
}

#[test]
fn merkle_inclusion_supports_non_power_of_two_tree() {
    use zk_state_anchor_exp::log::MerkleLog;
    let mut log = MerkleLog::new("unit-log");
    for i in 0..7u8 {
        log.append(vec![i]);
    }
    let root = log.root();
    for i in 0..7 {
        let p = log.inclusion_proof(i).unwrap();
        assert!(p.verify(&root), "index {i}");
    }
}
