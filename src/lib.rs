//! EXP-D2-B-01: ZkStateAnchor 协议与参考实现。
//!
//! 本 crate 只做协议数据结构、规范化编码、外部验证器与攻击测试；
//! 不修改 D1-E 或 D2-A，也不在 Halo2 电路内实现 SHA-256。

pub mod anchor;
pub mod checkpoint;
pub mod encoding;
pub mod errors;
pub mod freshness;
pub mod log;
pub mod quorum;
pub mod scenarios;
pub mod verifier;
