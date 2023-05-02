use async_trait::async_trait;
use std::time::Duration;

/// A trait allowing definition of the asnychronous `sleep`
/// operation of your choice. It should be implemented
/// using the `async_trait` crate.
///
/// Most users should simply use `tokio::sleep` by enabling
/// the `tokio` feature and using [`Client::with_tokio`](crate::Client::with_tokio)
#[async_trait]
pub trait Sleeper {
    async fn sleep(&self, duration: Duration);
}

#[cfg(feature = "tokio")]
pub struct TokioSleeper;

#[cfg(feature = "tokio")]
#[async_trait]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await
    }
}
