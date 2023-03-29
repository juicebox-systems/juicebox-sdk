use futures::future::join_all;
use loam_sdk_core::{
    DeleteRequest, DeleteResponse, GenerationNumber, SecretsRequest, SecretsResponse,
};
use tracing::instrument;

use crate::request::RequestError;
use crate::{HttpClient, Loam, Realm};

/// Error return type for [`Client::delete_all`].
#[derive(Debug)]
pub enum DeleteError {
    /// A transient error in sending or receiving requests to a realm.
    NetworkError,

    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// The provided URL for the realm was unable to be parsed.
    InvalidRealmUrl,
}

impl<Http: HttpClient> Loam<Http> {
    /// Deletes all secrets for this user up to and excluding the given
    /// generation number.
    ///
    /// If the generation number is given as `None`, deletes all the user's
    /// generations.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    pub(crate) async fn delete_up_to(
        &self,
        up_to: Option<GenerationNumber>,
    ) -> Result<(), DeleteError> {
        let requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.delete_on_realm(realm, up_to));

        // Use `join_all` instead of `try_join_all` so that a failed delete
        // request does not short-circuit other requests (which may still
        // succeed).
        join_all(requests).await.into_iter().collect()
    }

    /// Executes [`delete_up_to`](Self::delete_up_to) on a particular realm.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn delete_on_realm(
        &self,
        realm: &Realm,
        up_to: Option<GenerationNumber>,
    ) -> Result<(), DeleteError> {
        let delete_result = self
            .make_request(realm, SecretsRequest::Delete(DeleteRequest { up_to }))
            .await;

        match delete_result {
            Err(RequestError::Network) => Err(DeleteError::NetworkError),
            Err(RequestError::DeserializationError(_))
            | Err(RequestError::SerializationError(_)) => todo!(),
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => Err(DeleteError::InvalidAuth),
            Err(RequestError::InvalidRealmUrl) => Err(DeleteError::InvalidRealmUrl),

            Ok(SecretsResponse::Delete(dr)) => match dr {
                DeleteResponse::Ok => Ok(()),
            },
            Ok(_) => todo!(),
        }
    }
}
