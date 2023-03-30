//! Register and recover PIN-protected secrets on behalf of a particular user.
//! See [`Client`].

mod delete;
mod recover;
mod register;
mod request;
mod types;

pub use delete::DeleteError;
pub use loam_sdk_core::types::{AuthToken, Policy};
pub use loam_sdk_networking::http;
pub use recover::RecoverError;
pub use register::RegisterError;
pub use types::{Configuration, Pin, Realm, UserSecret};

use std::fmt::Debug;
use tracing::instrument;

use crate::types::CheckedConfiguration;

/// Used to register and recover PIN-protected secrets on behalf of a
/// particular user.
#[derive(Debug)]
pub struct Client<Http: http::Client> {
    pub(crate) configuration: CheckedConfiguration,
    pub auth_token: AuthToken,
    pub http: Http,
}

impl<Http: http::Client> Client<Http> {
    /// Constructs a new `Client`.
    ///
    /// The configuration provided must include at least one realm.
    ///
    /// The `auth_token` represents the authority to act as a particular user
    /// and should be valid for the lifetime of the `Client`.
    pub fn new(configuration: Configuration, auth_token: AuthToken, http: Http) -> Self {
        Self {
            configuration: CheckedConfiguration::from(configuration),
            auth_token,
            http,
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
        self.recover_latest_available_generation(pin).await
    }

    /// Deletes all secrets for this user.
    ///
    /// Note: This does not delete the user's audit log.
    pub async fn delete_all(&self) -> Result<(), DeleteError> {
        self.delete_up_to(None).await
    }
}