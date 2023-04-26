use async_trait::async_trait;
use std::time::Duration;

#[async_trait(?Send)]
pub trait Sleeper {
    async fn sleep(&self, duration: Duration);
}
