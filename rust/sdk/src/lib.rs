#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::instrument;

mod auth;
mod configuration;
mod delete;
mod pin;
mod recover;
mod register;
mod request;
mod sleeper;
mod types;

use configuration::CheckedConfiguration;
use types::Session;

pub use auth::AuthTokenManager;
pub use configuration::Configuration;
pub use delete::DeleteError;
/// A unique identifier for a [`Realm`].
#[doc = "\n"] // add paragraph break before core crate comment
pub use juicebox_api::types::RealmId;
pub use juicebox_api::types::{AuthToken, Policy};
pub use juicebox_networking::http;
pub use pin::{Pin, PinHashingMode};
pub use recover::RecoverError;
pub use register::RegisterError;
pub use sleeper::Sleeper;
pub use types::{Realm, UserInfo, UserSecret};

#[cfg(feature = "tokio")]
pub use sleeper::TokioSleeper;

#[cfg(feature = "reqwest")]
pub use juicebox_networking::reqwest;
#[cfg(feature = "reqwest")]
use juicebox_networking::rpc::LoadBalancerService;

/// Used to build a [`Client`].
pub struct ClientBuilder<S, Http, Atm> {
    configuration: Option<CheckedConfiguration>,
    previous_configurations: Vec<CheckedConfiguration>,
    auth_token_manager: Option<Atm>,
    http: Option<Http>,
    sleeper: Option<S>,
}

impl<S, Http, Atm> Default for ClientBuilder<S, Http, Atm>
where
    S: Sleeper,
    Http: http::Client,
    Atm: auth::AuthTokenManager,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S, Http, Atm> ClientBuilder<S, Http, Atm>
where
    S: Sleeper,
    Http: http::Client,
    Atm: auth::AuthTokenManager,
{
    /// Constructs a new `ClientBuilder`.
    pub fn new() -> Self {
        ClientBuilder {
            configuration: None,
            previous_configurations: Vec::new(),
            auth_token_manager: None,
            http: None,
            sleeper: None,
        }
    }

    /// Sets the current configuration. The configuration provided must include at least one [`Realm`]
    pub fn configuration(mut self, configuration: Configuration) -> Self {
        self.configuration = Some(CheckedConfiguration::from(configuration));
        self
    }

    /// Sets any configurations you have previously registered with that you may not yet have
    /// migrated secrets from to the current configuration. During [`Client::recover`], they
    /// will be tried if the current user has not yet registered on the current configuration.
    /// These should be ordered from most recently to least recently used.
    pub fn previous_configurations(mut self, previous_configurations: Vec<Configuration>) -> Self {
        self.previous_configurations = previous_configurations
            .into_iter()
            .map(CheckedConfiguration::from)
            .collect();
        self
    }

    /// Sets the [`AuthTokenManager`] used to authenticate requests on a given [`Realm`].
    pub fn auth_token_manager(mut self, auth_token_manager: Atm) -> Self {
        self.auth_token_manager = Some(auth_token_manager);
        self
    }

    /// Sets an [`http::Client`] used to make [`http::Request`] to a [`Realm`].
    pub fn http(mut self, http: Http) -> Self {
        self.http = Some(http);
        self
    }

    /// Sets a [`Sleeper`] to use when the `Client` needs to perform sleep operations.
    pub fn sleeper(mut self, sleeper: S) -> Self {
        self.sleeper = Some(sleeper);
        self
    }

    /// Constructs a new [`Client`].
    pub fn build(self) -> Client<S, Http, Atm> {
        let configuration = self.configuration.expect("configuration is required");
        let auth_token_manager = self
            .auth_token_manager
            .expect("auth_token_manager is required");
        let http = self.http.expect("http_client is required");
        let sleeper = self.sleeper.expect("sleeper is required");
        let sessions = configuration
            .realms
            .iter()
            .map(|realm| (realm.id, Mutex::new(None)))
            .collect();

        Client {
            configuration,
            previous_configurations: self.previous_configurations,
            auth_token_manager,
            http,
            sleeper,
            sessions,
        }
    }
}

#[cfg(feature = "tokio")]
impl<Http, Atm> ClientBuilder<TokioSleeper, Http, Atm>
where
    Http: http::Client,
    Atm: auth::AuthTokenManager,
{
    /// Configures the [`Client`] to use the tokio runtime for sleep operations.
    pub fn tokio_sleeper(self) -> Self {
        self.sleeper(TokioSleeper)
    }
}

#[cfg(feature = "reqwest")]
impl<S, Atm> ClientBuilder<S, reqwest::Client<LoadBalancerService>, Atm>
where
    S: Sleeper,
    Atm: auth::AuthTokenManager,
{
    /// Sets the [`http::Client`] to [`reqwest::Client`].
    pub fn reqwest(self) -> Self {
        self.http(reqwest::Client::<LoadBalancerService>::new(
            reqwest::ClientOptions::default(),
        ))
    }

    /// Sets the [`http::Client`] to [`reqwest::Client`] with the supplied [`reqwest::ClientOptions`].
    pub fn reqwest_with_options(self, options: reqwest::ClientOptions) -> Self {
        self.http(reqwest::Client::<LoadBalancerService>::new(options))
    }
}

/// Used to register and recover PIN-protected secrets on behalf of a
/// particular user.
pub struct Client<S: Sleeper, Http: http::Client, Atm: auth::AuthTokenManager> {
    configuration: CheckedConfiguration,
    previous_configurations: Vec<CheckedConfiguration>,
    auth_token_manager: Atm,
    http: Http,
    sleeper: S,
    sessions: HashMap<RealmId, Mutex<Option<Session>>>,
}

impl<S: Sleeper, Http: http::Client, Atm: auth::AuthTokenManager> Client<S, Http, Atm> {
    /// Stores a new PIN-protected secret on the configured realms.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    pub async fn register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        info: &UserInfo,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        self.perform_register(pin, secret, info, policy).await
    }

    /// Retrieves a PIN-protected secret from the configured realms, or falls
    /// back to the previous realms if the current realms do not have a secret
    /// registered.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    pub async fn recover(&self, pin: &Pin, info: &UserInfo) -> Result<UserSecret, RecoverError> {
        self.perform_recover(pin, info).await
    }

    /// Deletes the registered secret for this user, if any.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    pub async fn delete(&self) -> Result<(), DeleteError> {
        self.perform_delete().await
    }
}
