use zk_state_anchor_exp::errors::VerifyResult;
use zk_state_anchor_exp::scenarios::by_id;
use zk_state_anchor_exp::verifier::verify_authz_state_anchor;

/// 运行指定场景并断言其实际结果与任务包预期一致；返回完整轨迹供测试检查失败点。
pub fn check(id: &str) -> VerifyResult {
    let scenario = by_id(id);
    let result = verify_authz_state_anchor(&scenario.request);
    assert_eq!(
        result.accepted, scenario.expected_accepted,
        "{} acceptance mismatch: reason={:?}\n{}",
        id, result.reason, result.trace.join("\n")
    );
    assert_eq!(
        result.reason, scenario.expected_reason,
        "{} reason mismatch\n{}",
        id, result.trace.join("\n")
    );
    result
}

pub fn reason_code(result: &VerifyResult) -> &'static str {
    result.reason.map(|r| r.code()).unwrap_or("ACCEPT")
}
