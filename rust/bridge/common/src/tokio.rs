use async_trait::async_trait;
use std::time::Duration;
use tokio::runtime::Runtime;

use loam_sdk as sdk;

pub struct Client<HttpClient: sdk::http::Client> {
    pub sdk: sdk::Client<TokioSleeper, HttpClient>,
    pub runtime: Runtime,
}

impl<HttpClient: sdk::http::Client> Client<HttpClient> {
    pub fn new(sdk: sdk::Client<TokioSleeper, HttpClient>) -> Self {
        Self {
            sdk,
            runtime: Runtime::new().unwrap(),
        }
    }
}

pub struct TokioSleeper;

#[async_trait(?Send)]
impl sdk::Sleeper for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await
    }
}
