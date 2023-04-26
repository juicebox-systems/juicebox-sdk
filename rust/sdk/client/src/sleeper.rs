use async_trait::async_trait;
use std::time::Duration;

#[async_trait(?Send)]
pub trait Sleeper {
    async fn sleep(&self, duration: Duration);
}

#[cfg(feature = "tokio")]
pub struct TokioSleeper;

#[cfg(feature = "tokio")]
#[async_trait(?Send)]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await
    }
}
