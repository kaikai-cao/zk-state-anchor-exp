//! EXP-D2-B-R1 / W01–W10：可信见证者集合绑定攻击矩阵。
//!
//! 所有拒绝都断言具体 QcError 码；验证器层的关键用例另断言原因码与 trace 细分码。

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zk_state_anchor_exp::checkpoint::{
    checkpoint_hash, encode_d1e_checkpoint, Checkpoint, CHAIN_ID,
};
use zk_state_anchor_exp::encoding::{u32be, Hash32};
use zk_state_anchor_exp::quorum::{QuorumCertificate, TestQuorumSigner, THRESHOLD};
use zk_state_anchor_exp::scenarios::by_id;
use zk_state_anchor_exp::verifier::verify_authz_state_anchor;
use zk_state_anchor_exp::witness_set::{QcError, TrustedWitnessSet};

const VECTORS: &str = include_str!("vectors/witness_set_vectors.json");

fn base_signer() -> TestQuorumSigner {
    TestQuorumSigner::new_test_signer()
}

fn trusted(signer: &TestQuorumSigner) -> TrustedWitnessSet {
    TrustedWitnessSet::from_verifying_keys_for_tests(&signer.publics, THRESHOLD)
}

fn checkpoint_for(set: &TrustedWitnessSet) -> Checkpoint {
    Checkpoint {
        chain_id: CHAIN_ID.to_string(),
        epoch: 8,
        previous_hash: Hash32::from_label("witness-test-prev"),
        state_root: Hash32::from_label("witness-test-state"),
        log_root: Hash32::from_label("witness-test-log"),
        policy_version: "1".to_string(),
        witness_set_root: set.compute_root(),
        log_size: 3,
        timestamp: 1000,
    }
}

fn rogue_signature(id: &str, cp: &Checkpoint) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(b"EXP-D2-B-R1-ROGUE-SEED");
    h.update(id.as_bytes());
    let bytes: [u8; 32] = h.finalize().into();
    let key = SigningKey::from_bytes(&bytes);
    key.sign(&encode_d1e_checkpoint(cp)).to_bytes()
}

// --- 最小 JSON 读取：只解析本项目生成的固定向量，不引入新依赖 -----------------

fn extract_strings(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            i = start;
            while i < bytes.len() {
                if bytes[i] == b'"' && bytes[i - 1] != b'\\' {
                    out.push(block[start..i].to_string());
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn json_field_string(json: &str, key: &str) -> String {
    let needle = format!("\"{}\":", key);
    let pos = json
        .find(&needle)
        .unwrap_or_else(|| panic!("missing JSON field {key}"));
    let rest = json[pos + needle.len()..].trim_start();
    let start = rest.find('"').expect("string value") + 1;
    let tail = &rest[start..];
    let mut end = 0;
    while end < tail.len() {
        if tail.as_bytes()[end] == b'"' && (end == 0 || tail.as_bytes()[end - 1] != b'\\') {
            break;
        }
        end += 1;
    }
    tail[..end].to_string()
}

fn json_field_array(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\":", key);
    let pos = json
        .find(&needle)
        .unwrap_or_else(|| panic!("missing JSON field {key}"));
    let rest = &json[pos + needle.len()..];
    let start = rest.find('[').expect("array value");
    let end = rest[start..].find(']').expect("array end") + start;
    extract_strings(&rest[start + 1..end])
}

fn vector_entries(json: &str) -> Vec<(String, String)> {
    let needle = "\"witnesses\":";
    let pos = json.find(needle).expect("witnesses array");
    let rest = &json[pos + needle.len()..];
    let start = rest.find('[').expect("array value");
    let end = rest[start..].find(']').expect("array end") + start;
    let strings: Vec<String> = extract_strings(&rest[start + 1..end])
        .into_iter()
        .filter(|s| s != "id" && s != "public_key_hex")
        .collect();
    strings
        .chunks(2)
        .map(|c| (c[0].clone(), c[1].clone()))
        .collect()
}

fn set_from_vectors(json: &str) -> TrustedWitnessSet {
    use ed25519_dalek::VerifyingKey;
    let entries: Vec<(String, VerifyingKey)> = vector_entries(json)
        .iter()
        .map(|(id, hex_key)| {
            let raw: [u8; 32] = hex::decode(hex_key)
                .expect("32-byte public key")
                .try_into()
                .unwrap();
            (
                id.clone(),
                VerifyingKey::from_bytes(&raw).expect("valid Ed25519 public key"),
            )
        })
        .collect();
    TrustedWitnessSet::from_verifying_keys_for_tests(&entries, THRESHOLD)
}

// --- W01–W10 ------------------------------------------------------------------

#[test]
fn w01_correct_witness_set_and_qc_accepts() {
    let signer = base_signer();
    let set = trusted(&signer);
    let cp = checkpoint_for(&set);
    let qc = signer.make_qc(&cp);
    assert_eq!(set.verify_qc(&qc, &cp), Ok(()));
    assert_eq!(checkpoint_hash(&cp), qc.checkpoint_hash);
    assert_eq!(set.compute_root(), cp.witness_set_root);
}

#[test]
fn w02_checkpoint_witness_set_root_replaced_rejected() {
    let signer = base_signer();
    let set = trusted(&signer);
    let mut cp = checkpoint_for(&set);
    cp.witness_set_root = Hash32::from_label("swapped-checkpoint-root");
    let qc = signer.make_qc(&cp);
    let err = set.verify_qc(&qc, &cp).unwrap_err();
    assert_eq!(err, QcError::CheckpointWitnessSetRootMismatch);
    assert_eq!(err.code(), "WITNESS_SET_ROOT_MISMATCH");
}

#[test]
fn w03_one_public_key_replaced_with_original_qc_rejected() {
    let signer = base_signer();
    let set = trusted(&signer);
    let cp = checkpoint_for(&set);
    let qc = signer.make_qc(&cp);

    let mut altered = set.clone();
    let rogue = SigningKey::from_bytes(&[0x42u8; 32]).verifying_key();
    altered.witnesses[0].public_key = rogue;
    // 即使调用方同时把 expected_root 改成新集合的根，checkpoint 声明的根仍是原集合。
    altered.expected_root = altered.compute_root();
    let err = altered.verify_qc(&qc, &cp).unwrap_err();
    assert_eq!(err, QcError::CheckpointWitnessSetRootMismatch);
    assert_eq!(err.code(), "WITNESS_SET_ROOT_MISMATCH");
}

#[test]
fn w04_unauthorized_witness_id_rejected() {
    let signer = base_signer();
    let set = trusted(&signer);
    let cp = checkpoint_for(&set);
    let mut qc = signer.make_qc(&cp);
    qc.signatures[2] = (
        "ROGUE-WITNESS".to_string(),
        rogue_signature("ROGUE-WITNESS", &cp),
    );
    let err = set.verify_qc(&qc, &cp).unwrap_err();
    assert_eq!(err, QcError::UntrustedWitnessId);
    assert_eq!(err.code(), "UNTRUSTED_WITNESS_ID");
}

#[test]
fn w05_duplicate_witness_id_not_counted_twice() {
    let signer = base_signer();
    let set = trusted(&signer);
    let cp = checkpoint_for(&set);
    let mut qc = signer.make_qc(&cp);
    qc.signatures[2].0 = qc.signatures[0].0.clone();
    qc.signatures[2].1 = qc.signatures[0].1;
    assert_eq!(qc.signatures.len(), 3);
    let err = set.verify_qc(&qc, &cp).unwrap_err();
    assert_eq!(err, QcError::DuplicateWitnessId);
    assert_eq!(err.code(), "DUPLICATE_WITNESS_ID");
}

#[test]
fn w06_only_two_valid_signatures_rejected() {
    let signer = base_signer();
    let set = trusted(&signer);
    let cp = checkpoint_for(&set);
    let mut qc = signer.make_qc(&cp);
    qc.signatures.truncate(2);
    let err = set.verify_qc(&qc, &cp).unwrap_err();
    assert_eq!(err, QcError::InsufficientSignatures);
    assert_eq!(err.code(), "INSUFFICIENT_SIGNATURES");
}

#[test]
fn w07_three_signatures_one_tampered_rejected() {
    let signer = base_signer();
    let set = trusted(&signer);
    let cp = checkpoint_for(&set);
    let mut qc = signer.make_qc(&cp);
    qc.signatures[1].1[17] ^= 0x01;
    let err = set.verify_qc(&qc, &cp).unwrap_err();
    assert_eq!(err, QcError::InvalidSignature);
    assert_eq!(err.code(), "INVALID_SIGNATURE");
}

#[test]
fn w08_public_key_order_does_not_change_root() {
    let set = set_from_vectors(VECTORS);
    let mut reversed = set.clone();
    reversed.witnesses.reverse();
    assert_eq!(set.compute_root(), reversed.compute_root());

    let pre = json_field_array(VECTORS, "pre_sort_order");
    let post = json_field_array(VECTORS, "post_sort_order");
    assert_eq!(
        TrustedWitnessSet::encode_root_input(&pre),
        TrustedWitnessSet::encode_root_input(&post)
    );
    assert_eq!(
        set.compute_root(),
        Hash32::from_hex(&json_field_string(VECTORS, "python_witness_set_root")).unwrap()
    );
}

#[test]
fn w09_rust_root_matches_python_vector_and_wrong_encoding_is_rejected() {
    let set = set_from_vectors(VECTORS);
    let python_root = json_field_string(VECTORS, "python_witness_set_root");
    let rust_root = set.compute_root().to_hex();
    println!("PYTHON_WITNESS_SET_ROOT={}", python_root);
    println!("RUST_WITNESS_SET_ROOT={}", rust_root);
    assert_eq!(
        rust_root, python_root,
        "Rust witness set root 必须与 D1-E Python 逐字节一致"
    );
    assert_eq!(
        json_field_string(VECTORS, "rust_witness_set_root"),
        rust_root
    );

    let encoding =
        TrustedWitnessSet::encode_root_input(&json_field_array(VECTORS, "pre_sort_order"));
    assert_eq!(
        hex::encode(&encoding),
        json_field_string(VECTORS, "encoding_hex")
    );
    assert_eq!(encoding.len(), 4 * (8 + 64));

    // 错误编码向量：4 字节长度前缀 + 未排序，必须得到不同根（不能放行）。
    let pre = json_field_array(VECTORS, "pre_sort_order");
    let mut wrong = Vec::new();
    for key in pre {
        wrong.extend_from_slice(&u32be(key.len() as u32));
        wrong.extend_from_slice(key.as_bytes());
    }
    let wrong_root = Sha256::digest(&wrong);
    assert_ne!(hex::encode(wrong_root), python_root);
}

#[test]
fn w10_different_witness_set_replacement_rejected() {
    let honest = base_signer();
    let set = trusted(&honest);
    let cp = checkpoint_for(&set);

    // R2 起单钥多 ID 在构造期拒绝，因此这里的“另一组集合”也必须使用 4 把不同公钥。
    let rogue_keys: Vec<SigningKey> = (1..=4u8)
        .map(|i| SigningKey::from_bytes(&[0x70 + i; 32]))
        .collect();
    let rogue_entries: Vec<(String, ed25519_dalek::VerifyingKey)> = rogue_keys
        .iter()
        .enumerate()
        .map(|(i, key)| (format!("W{}", i + 1), key.verifying_key()))
        .collect();
    let rogue_set = TrustedWitnessSet::from_verifying_keys_for_tests(&rogue_entries, THRESHOLD);
    let mut rogue_cp = cp.clone();
    rogue_cp.witness_set_root = rogue_set.compute_root();
    let data = encode_d1e_checkpoint(&rogue_cp);
    let rogue_qc = QuorumCertificate {
        checkpoint_hash: checkpoint_hash(&rogue_cp),
        epoch: rogue_cp.epoch,
        previous_hash: rogue_cp.previous_hash,
        signatures: rogue_keys
            .iter()
            .take(THRESHOLD)
            .enumerate()
            .map(|(i, key)| (format!("W{}", i + 1), key.sign(&data).to_bytes()))
            .collect(),
    };
    let err = set.verify_qc(&rogue_qc, &rogue_cp).unwrap_err();
    assert_eq!(err, QcError::CheckpointWitnessSetRootMismatch);
    assert_ne!(rogue_set.compute_root(), set.compute_root());
}

// --- 验证器层：信任绑定必须在验签之前生效 --------------------------------------

#[test]
fn verifier_w01_accepts_and_records_binding() {
    let scenario = by_id("T01");
    let result = verify_authz_state_anchor(&scenario.request);
    assert!(result.accepted);
    assert!(result
        .trace
        .iter()
        .any(|s| s.contains("witness_set_binding") && s.contains("code=OK")));
}

#[test]
fn verifier_w02_replaced_root_rejects_with_specific_code() {
    let scenario = by_id("T01");
    let mut req = scenario.request;
    req.checkpoint.witness_set_root = Hash32::from_label("attacker-root");
    let result = verify_authz_state_anchor(&req);
    assert!(!result.accepted);
    assert_eq!(
        result.reason.expect("reason").code(),
        "INVALID_QUORUM_CERTIFICATE"
    );
    assert!(result
        .trace
        .iter()
        .any(|s| s.contains("WITNESS_SET_ROOT_MISMATCH")));
}

#[test]
fn verifier_w03_changed_trusted_key_rejects_with_specific_code() {
    let scenario = by_id("T01");
    let mut req = scenario.request;
    req.trusted_witness_set.witnesses[0].public_key =
        SigningKey::from_bytes(&[0x11u8; 32]).verifying_key();
    let result = verify_authz_state_anchor(&req);
    assert!(!result.accepted);
    assert_eq!(
        result.reason.expect("reason").code(),
        "INVALID_QUORUM_CERTIFICATE"
    );
    assert!(result
        .trace
        .iter()
        .any(|s| s.contains("TRUSTED_SET_ROOT_MISMATCH")));
}
