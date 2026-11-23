//! Freshness Provider 接口与三个测试 Provider。
//!
//! 这些实现只是模拟：它们不连接任何真实网络服务，也不证明最新性。
//! 验证器把 freshness 作为外部信任假设；provider 不可用或给出旧 checkpoint 时一律拒绝。

use crate::checkpoint::checkpoint_hash;
use crate::encoding::Hash32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCheckpoint {
    pub epoch: u64,
    pub checkpoint_hash: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreshnessError {
    Unavailable,
}

pub trait FreshnessProvider {
    fn label(&self) -> &'static str;
    fn get_latest_checkpoint(&self) -> Result<TrustedCheckpoint, FreshnessError>;
}

pub struct HonestFreshnessProvider {
    latest: TrustedCheckpoint,
}

impl HonestFreshnessProvider {
    pub fn for_checkpoint(cp: &crate::checkpoint::Checkpoint) -> Self {
        Self { latest: TrustedCheckpoint { epoch: cp.epoch, checkpoint_hash: checkpoint_hash(cp) } }
    }
}

impl FreshnessProvider for HonestFreshnessProvider {
    fn label(&self) -> &'static str {
        "HonestFreshnessProvider"
    }

    fn get_latest_checkpoint(&self) -> Result<TrustedCheckpoint, FreshnessError> {
        Ok(self.latest.clone())
    }
}

pub struct StaleFreshnessProvider {
    stale: TrustedCheckpoint,
}

impl StaleFreshnessProvider {
    pub fn from_values(epoch: u64, checkpoint_hash: Hash32) -> Self {
        Self { stale: TrustedCheckpoint { epoch, checkpoint_hash } }
    }
}

impl FreshnessProvider for StaleFreshnessProvider {
    fn label(&self) -> &'static str {
        "StaleFreshnessProvider"
    }

    fn get_latest_checkpoint(&self) -> Result<TrustedCheckpoint, FreshnessError> {
        Ok(self.stale.clone())
    }
}

pub struct UnavailableFreshnessProvider;

impl FreshnessProvider for UnavailableFreshnessProvider {
    fn label(&self) -> &'static str {
        "UnavailableFreshnessProvider"
    }

    fn get_latest_checkpoint(&self) -> Result<TrustedCheckpoint, FreshnessError> {
        Err(FreshnessError::Unavailable)
    }
}
