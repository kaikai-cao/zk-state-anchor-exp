//! 运行 T01–T20 并把逐项结果、正常路径与回滚攻击的完整执行轨迹写入 JSON。
//! 报告由 tools/export_report.py 读取该 JSON 生成，避免报告与测试漂移。

use std::fs;

use zk_state_anchor_exp::scenarios::all_scenarios;
use zk_state_anchor_exp::verifier::verify_authz_state_anchor;

fn esc(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn trace_json(trace: &[String]) -> String {
    let items: Vec<String> = trace.iter().map(|s| format!("\"{}\"", esc(s))).collect();
    format!("[{}]", items.join(","))
}

fn main() {
    let scenarios = all_scenarios();
    let mut rows = Vec::new();
    let mut normal = Vec::new();
    let mut rollback = Vec::new();

    for s in &scenarios {
        let result = verify_authz_state_anchor(&s.request);
        let reason = result.reason.map(|r| r.code()).unwrap_or("ACCEPT");
        let expected_reason = s.expected_reason.map(|r| r.code()).unwrap_or("ACCEPT");
        let matched = result.accepted == s.expected_accepted && reason == expected_reason;
        println!(
            "{} | {} | expected={} actual={} | {}",
            s.id,
            s.title,
            expected_reason,
            reason,
            if matched { "OK" } else { "MISMATCH" }
        );
        if !matched {
            panic!("scenario {} outcome mismatch", s.id);
        }
        rows.push(format!(
            "{{\"id\":\"{}\",\"title\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"accepted\":{},\"trace\":{}}}",
            s.id, esc(s.title), expected_reason, reason, result.accepted, trace_json(&result.trace)
        ));
        if s.id == "T01" {
            normal = result.trace.clone();
        }
        if s.id == "T14" {
            rollback = result.trace.clone();
        }
    }

    let json = format!(
        "{{\"experiment\":\"EXP-D2-B-01\",\"scenario_count\":{},\"results\":[{}],\"execution_records\":{{\"normal_path_T01\":{},\"rollback_attack_T14\":{}}}}}\n",
        scenarios.len(),
        rows.join(","),
        trace_json(&normal),
        trace_json(&rollback)
    );
    fs::write("results/verification_results.json", json).expect("write verification_results.json");
    println!(
        "wrote results/verification_results.json ({} scenarios)",
        scenarios.len()
    );
}
