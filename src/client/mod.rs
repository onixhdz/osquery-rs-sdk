mod manager;
mod named_pipe;

pub use manager::{ExtensionInfo, ExtensionManager, ExtensionManagerClient, OptionInfo};

/// Seals [`ExtensionManager`] so external crates cannot implement it. The
/// module is unreachable outside the crate, which keeps the trait's contract
/// evolvable without breaking downstream implementations.
pub mod sealed {
    pub trait Sealed {}
}
