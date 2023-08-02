use tokio::runtime::Runtime;

use juicebox_sdk as sdk;

pub struct Client<HttpClient: sdk::http::Client, Atm: sdk::AuthTokenManager> {
    pub sdk: sdk::Client<sdk::TokioSleeper, HttpClient, Atm>,
    pub runtime: Runtime,
}

impl<HttpClient: sdk::http::Client, Atm: sdk::AuthTokenManager> Client<HttpClient, Atm> {
    pub fn new(sdk: sdk::Client<sdk::TokioSleeper, HttpClient, Atm>) -> Self {
        Self {
            sdk,
            runtime: Runtime::new().unwrap(),
        }
    }
}
