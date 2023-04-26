//! Register and recover PIN-protected secrets on behalf of a particular user.
//! See [`Client`].
#![cfg_attr(not(feature = "wasm"), allow(clippy::disallowed_methods))]

use std::collections::HashMap;
use std::fmt::Debug;
use tokio::sync::Mutex;
use tracing::instrument;

mod delete;
mod pin;
mod recover;
mod register;
mod request;
mod types;

use types::{CheckedConfiguration, Session};

pub use delete::DeleteError;
pub use loam_sdk_core::types::{AuthToken, Policy, RealmId};
pub use loam_sdk_networking::http;
pub use pin::{HashedPin, Pin, PinHashingMode};
pub use recover::RecoverError;
pub use register::RegisterError;
pub use types::{Configuration, Realm, UserSecret};

/// Used to register and recover PIN-protected secrets on behalf of a
/// particular user.
#[derive(Debug)]
pub struct Client<Http: http::Client> {
    configuration: CheckedConfiguration,
    previous_configurations: Vec<CheckedConfiguration>,
    auth_token: AuthToken,
    http: Http,
    sessions: HashMap<RealmId, Mutex<Option<Session>>>,
}

impl<Http: http::Client> Client<Http> {
    /// Constructs a new `Client`.
    ///
    /// The configuration provided must include at least one realm.
    ///
    /// The `previous_configurations` parameter represents any other
    /// configurations you have previously registered with that you may not yet
    /// have migrated the data from. During recovery, they will be tried if the
    /// current user has not yet registered on the current configuration. They
    /// should be ordered from newest to oldest.
    ///
    /// The `auth_token` represents the authority to act as a particular user
    /// and should be valid for the lifetime of the `Client`.
    pub fn new(
        configuration: Configuration,
        previous_configurations: Vec<Configuration>,
        auth_token: AuthToken,
        http: Http,
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
            auth_token,
            http,
            sessions,
        }
    }

    /// Stores a new PIN-protected secret.
    ///
    /// If it's successful, this also deletes any prior secrets for this user.
    ///
    /// # Warning
    ///
    /// If the secrets vary in length (such as passwords), the caller should
    /// add padding to obscure the secrets' length.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    pub async fn register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        self.register_first_available_generation(pin, secret, policy)
            .await
    }

    /// Retrieves a PIN-protected secret.
    ///
    /// If it's successful, this also deletes any earlier secrets for this
    /// user.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    pub async fn recover(&self, pin: &Pin) -> Result<UserSecret, RecoverError> {
        self.recover_latest_registered_configuration(pin).await
    }

    /// Deletes all secrets for this user.
    ///
    /// Note: This does not delete the user's audit log.
    pub async fn delete_all(&self) -> Result<(), DeleteError> {
        self.delete_up_to(None).await
    }
}
