//! 跨语言一致性探针：输出固定 checkpoint 的编码 hex 与 checkpoint_hash，
//! 供与 D1-E Python `src/canonical.py:encode_checkpoint` 逐字节比对。

use zk_state_anchor_exp::checkpoint::{checkpoint_hash, encode_d1e_checkpoint, Checkpoint};
use zk_state_anchor_exp::encoding::Hash32;

fn main() {
    let cp = Checkpoint {
        chain_id: "c".to_string(),
        epoch: 1,
        previous_hash: Hash32([1u8; 32]),
        state_root: Hash32([2u8; 32]),
        log_root: Hash32([3u8; 32]),
        policy_version: "v1".to_string(),
        witness_set_root: Hash32([4u8; 32]),
        log_size: 2,
        timestamp: 5,
    };
    println!("encoding_hex={}", hex::encode(encode_d1e_checkpoint(&cp)));
    println!("checkpoint_hash={}", checkpoint_hash(&cp).to_hex());
}
