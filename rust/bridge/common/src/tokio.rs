use tokio::runtime::Runtime;

use loam_sdk as sdk;

pub struct Client<HttpClient: sdk::http::Client> {
    pub sdk: sdk::Client<sdk::TokioSleeper, HttpClient>,
    pub runtime: Runtime,
}

impl<HttpClient: sdk::http::Client> Client<HttpClient> {
    pub fn new(sdk: sdk::Client<sdk::TokioSleeper, HttpClient>) -> Self {
        Self {
            sdk,
            runtime: Runtime::new().unwrap(),
        }
    }
}
