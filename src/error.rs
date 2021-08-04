///!
/// Module which defines error which can happen within this crate.
use thiserror::Error;

/// Error type that describes all possible errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
}
