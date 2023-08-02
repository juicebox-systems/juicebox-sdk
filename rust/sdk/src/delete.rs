use futures::future::join_all;
use tracing::instrument;

use crate::{auth, http, request::RequestError, Client, Realm, Sleeper};
use juicebox_realm_api::requests::{DeleteResponse, SecretsRequest, SecretsResponse};

/// Error return type for [`Client::delete`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeleteError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion,

    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient,
}

impl<S: Sleeper, Http: http::Client, Atm: auth::AuthTokenManager> Client<S, Http, Atm> {
    pub(crate) async fn perform_delete(&self) -> Result<(), DeleteError> {
        let requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.delete_on_realm(realm));

        // Use `join_all` instead of `try_join_all` so that a failed delete
        // request does not short-circuit other requests (which may still
        // succeed).
        join_all(requests).await.into_iter().collect()
    }

    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn delete_on_realm(&self, realm: &Realm) -> Result<(), DeleteError> {
        let delete_result = self.make_request(realm, SecretsRequest::Delete).await;

        match delete_result {
            Err(RequestError::Transient) => Err(DeleteError::Transient),
            Err(RequestError::Assertion) => Err(DeleteError::Assertion),
            Err(RequestError::InvalidAuth) => Err(DeleteError::InvalidAuth),

            Ok(SecretsResponse::Delete(dr)) => match dr {
                DeleteResponse::Ok => Ok(()),
            },
            Ok(_) => Err(DeleteError::Assertion),
        }
    }
}
