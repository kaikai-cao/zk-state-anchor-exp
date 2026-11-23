mod common;

use common::{check, reason_code};
use zk_state_anchor_exp::scenarios::all_scenarios;
use zk_state_anchor_exp::verifier::verify_authz_state_anchor;

#[test]
fn t13_checkpoint_epoch_regression_rejected() {
    let r = check("T13");
    assert_eq!(reason_code(&r), "ANCHOR_EPOCH_MISMATCH");
}

#[test]
fn all_twenty_scenarios_match_task_package_expectations() {
    let scenarios = all_scenarios();
    assert_eq!(scenarios.len(), 20);
    for s in scenarios {
        let r = verify_authz_state_anchor(&s.request);
        assert_eq!(r.accepted, s.expected_accepted, "{} acceptance", s.id);
        assert_eq!(r.reason, s.expected_reason, "{} reason", s.id);
    }
}

#[test]
fn execution_record_normal_path_is_complete() {
    let r = check("T01");
    let joined = r.trace.join(" | ");
    for stage in [
        "anchor_digest", "public_inputs", "policy_binding", "log_inclusion",
        "quorum_certificate", "checkpoint_fields", "no_rollback", "anchor_predecessor",
        "freshness", "VERDICT: ACCEPT",
    ] {
        assert!(joined.contains(stage), "normal path trace missing {stage}");
    }
    println!("NORMAL_PATH_EXECUTION_RECORD:\n{}", r.trace.join("\n"));
}

#[test]
fn execution_record_rollback_attack_stops_before_freshness() {
    let r = check("T14");
    let joined = r.trace.join(" | ");
    assert!(joined.contains("CHECKPOINT_ROLLBACK"));
    assert!(joined.contains("known_epoch=9 offered_epoch=8"));
    // 早停：回滚检查失败后不应进入 freshness 步骤
    assert!(!joined.contains("[9/10] freshness"));
    println!("ROLLBACK_ATTACK_EXECUTION_RECORD:\n{}", r.trace.join("\n"));
}
