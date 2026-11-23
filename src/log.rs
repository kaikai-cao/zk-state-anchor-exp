//! RFC 6962 风格透明日志（仅 inclusion proof；本轮不实现 consistency proof）。
//!
//! - MTH({}) = SHA-256("")
//! - MTH({d}) = SHA-256(0x00 || d)
//! - MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))，k 为严格小于 n 的最大 2 幂
//!
//! 不支持“填充空节点凑满二叉树”的近似实现。

use crate::encoding::sha256;
use sha2::{Digest, Sha256};

pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + leaf.len());
    input.push(0x00);
    input.extend_from_slice(leaf);
    sha256(&[&input]).0
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(65);
    input.push(0x01);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&[&input]).0
}

pub fn empty_root() -> [u8; 32] {
    Sha256::digest(b"").into()
}

fn largest_power_of_two_below(n: usize) -> usize {
    assert!(n > 1);
    1usize << ((n - 1).ilog2())
}

pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = largest_power_of_two_below(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

fn audit_path(leaves: &[Vec<u8>], start: usize, m: usize, n: usize, proof: &mut Vec<[u8; 32]>) {
    if n == 1 {
        return;
    }
    let k = largest_power_of_two_below(n);
    if m < k {
        audit_path(leaves, start, m, k, proof);
        proof.push(merkle_root(&leaves[start + k..start + n]));
    } else {
        audit_path(leaves, start + k, m - k, n - k, proof);
        proof.push(merkle_root(&leaves[start..start + k]));
    }
}

fn audit_sides(m: usize, n: usize, sides: &mut Vec<bool>) {
    // true = sibling is on the right
    if n == 1 {
        return;
    }
    let k = largest_power_of_two_below(n);
    if m < k {
        audit_sides(m, k, sides);
        sides.push(true);
    } else {
        audit_sides(m - k, n - k, sides);
        sides.push(false);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub log_id: String,
    pub leaf: Vec<u8>,
    pub index: usize,
    pub tree_size: usize,
    pub siblings: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// 由 (index, tree_size) 推导兄弟节点方向，证明本身不携带方向元数据。
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        if self.index >= self.tree_size || self.tree_size == 0 {
            return false;
        }
        let mut sides = Vec::new();
        audit_sides(self.index, self.tree_size, &mut sides);
        if sides.len() != self.siblings.len() {
            return false;
        }
        let mut acc = leaf_hash(&self.leaf);
        for (sib, right) in self.siblings.iter().zip(sides) {
            acc = if right {
                node_hash(&acc, sib)
            } else {
                node_hash(sib, &acc)
            };
        }
        acc == *root
    }
}

#[derive(Clone, Debug)]
pub struct MerkleLog {
    pub log_id: String,
    pub leaves: Vec<Vec<u8>>,
}

impl MerkleLog {
    pub fn new(log_id: &str) -> Self {
        Self {
            log_id: log_id.to_string(),
            leaves: Vec::new(),
        }
    }

    pub fn append(&mut self, leaf: Vec<u8>) -> usize {
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.leaves)
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut siblings = Vec::new();
        audit_path(&self.leaves, 0, index, self.leaves.len(), &mut siblings);
        Some(InclusionProof {
            log_id: self.log_id.clone(),
            leaf: self.leaves[index].clone(),
            index,
            tree_size: self.leaves.len(),
            siblings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_works_for_non_power_of_two_tree() {
        let mut log = MerkleLog::new("test-log");
        for i in 0..5u8 {
            log.append(vec![i]);
        }
        assert_eq!(log.size(), 5);
        let root = log.root();
        for i in 0..5 {
            let proof = log.inclusion_proof(i).unwrap();
            assert!(proof.verify(&root), "index {i}");
            let mut bad = proof;
            bad.leaf = vec![99];
            assert!(!bad.verify(&root));
        }
    }
}
