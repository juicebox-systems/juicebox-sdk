#![doc = include_str!("../../../README.md")]

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
pub use juicebox_sdk_core::types::RealmId;
pub use juicebox_sdk_core::types::{AuthToken, Policy};
pub use juicebox_sdk_networking::http;
pub use pin::{Pin, PinHashingMode};
pub use recover::RecoverError;
pub use register::RegisterError;
pub use sleeper::Sleeper;
pub use types::{Realm, UserInfo, UserSecret};

#[cfg(feature = "tokio")]
pub use sleeper::TokioSleeper;

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

#[cfg(feature = "tokio")]
impl<Http: http::Client, Atm: auth::AuthTokenManager> Client<TokioSleeper, Http, Atm> {
    /// Constructs a new `Client` that uses the tokio runtime for delaying request retries.
    ///
    /// see also [`Client::new`]
    pub fn with_tokio(
        configuration: Configuration,
        previous_configurations: Vec<Configuration>,
        auth_token_manager: Atm,
        http: Http,
    ) -> Self {
        Self::new(
            configuration,
            previous_configurations,
            auth_token_manager,
            http,
            TokioSleeper,
        )
    }
}

impl<S: Sleeper, Http: http::Client, Atm: auth::AuthTokenManager> Client<S, Http, Atm> {
    /// Constructs a new `Client`.
    ///
    /// # Arguments
    ///
    /// * `configuration` – Represents the current configuration. The configuration
    /// provided must include at least one [`Realm`].
    /// * `previous_configurations` – Represents any other configurations you have
    /// previously registered with that you may not yet have migrated the data from.
    /// During [`Client::recover`], they will be tried if the current user has not yet
    /// registered on the current configuration. These should be ordered from most recently
    /// to least recently used.
    /// * `auth_token_manager` – An [`AuthTokenManager`] used to retrieve a token for
    /// a given [`Realm`].
    /// * `http` – An [`http::Client`] used to make [`http::Request`] to a [`Realm`].
    /// * `sleeper` – A [`Sleeper`] to use when the SDK needs to perform a `sleep` operation.
    pub fn new(
        configuration: Configuration,
        previous_configurations: Vec<Configuration>,
        auth_token_manager: Atm,
        http: Http,
        sleeper: S,
    ) -> Self {
        let configuration = CheckedConfiguration::from(configuration);
        let sessions = configuration
            .realms
            .iter()
            .map(|realm| (realm.id, Mutex::new(None)))
            .collect();
        Self {
            configuration,
            previous_configurations: previous_configurations
                .into_iter()
                .map(CheckedConfiguration::from)
                .collect(),
            auth_token_manager,
            http,
            sessions,
            sleeper,
        }
    }

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
