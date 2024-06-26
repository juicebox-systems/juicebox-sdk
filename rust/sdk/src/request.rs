use futures::{stream::FuturesUnordered, StreamExt};
use instant::Instant;
use rand::{rngs::OsRng, RngCore};
use std::error::Error;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::{collections::HashMap, time::Duration};
use tracing::instrument;
use x25519_dalek as x25519;

use crate::auth;
use crate::{http, types::Session, Client, Realm, Sleeper};
use juicebox_marshalling as marshalling;
use juicebox_networking::rpc::{self, RpcError, SendOptions};
use juicebox_noise::client as noise;
use juicebox_realm_api::{
    requests::{
        ClientRequest, ClientRequestKind, ClientResponse, NoiseRequest, NoiseResponse,
        PaddedSecretsResponse, SecretsRequest, SecretsResponse,
    },
    types::SessionId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// The SDK software is too old to communicate with this realm
    /// and must be upgraded.
    UpgradeRequired,

    /// The tenant has exceeded their allowed number of operations. Try again
    /// later.
    RateLimitExceeded,

    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient,

    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software,
    /// updates and try again.
    Assertion,
}

impl Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for RequestError {}

impl From<RpcError> for RequestError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::Network => Self::Transient,
            RpcError::HttpStatus(code) => match code {
                401 => Self::InvalidAuth,
                426 => Self::UpgradeRequired,
                429 => Self::RateLimitExceeded,
                _ => Self::Transient,
            },
            RpcError::Serialization(_) => Self::Assertion,
            RpcError::Deserialization(_) => Self::Assertion,
        }
    }
}

/// Error type for [`Client::make_transport_request`].
#[derive(Debug)]
enum RequestErrorOrMissingSession {
    RequestError(RequestError),
    MissingSession,
}

impl From<RequestError> for RequestErrorOrMissingSession {
    fn from(e: RequestError) -> Self {
        Self::RequestError(e)
    }
}

// Named flag.
#[derive(Clone, Copy, Debug)]
struct NeedsForwardSecrecy(bool);

impl<S: Sleeper, Http: http::Client, Atm: auth::AuthTokenManager> Client<S, Http, Atm> {
    #[instrument(
        level = "trace",
        skip(self, public_key, request),
        err(level = "trace", Debug)
    )]
    async fn make_handshake_request(
        &self,
        realm: &Realm,
        public_key: &Vec<u8>,
        request: &[u8],
    ) -> Result<(Session, Vec<u8>), RequestError> {
        let realm_public_key = {
            // Whether the public key looks valid is checked with the
            // `Configuration`, so it's OK to panic on that here.
            assert_eq!(public_key.len(), 32);
            let mut buf = [0u8; 32];
            buf.copy_from_slice(public_key);
            x25519::PublicKey::from(buf)
        };
        let (handshake, fields) = noise::Handshake::start(&realm_public_key, request, &mut OsRng)
            .map_err(|_| RequestError::Assertion)?;
        let session_id = SessionId(OsRng.next_u32());

        let auth_token = self
            .auth_token_manager
            .get(&realm.id)
            .await
            .ok_or(RequestError::InvalidAuth)?;

        match rpc::send(
            &self.http,
            &realm.address,
            ClientRequest {
                realm: realm.id,
                auth_token,
                session_id,
                kind: if request.is_empty() {
                    ClientRequestKind::HandshakeOnly
                } else {
                    ClientRequestKind::SecretsRequest
                },
                encrypted: NoiseRequest::Handshake { handshake: fields },
            },
        )
        .await?
        {
            ClientResponse::Ok(NoiseResponse::Handshake {
                handshake: handshake_response,
                session_lifetime,
            }) => {
                let (transport, response) = handshake
                    .finish(&handshake_response)
                    .map_err(|_| RequestError::Assertion)?;
                Ok((
                    Session {
                        session_id,
                        transport,
                        lifetime: session_lifetime,
                        last_used: Instant::now(),
                    },
                    response,
                ))
            }
            ClientResponse::Ok(NoiseResponse::Transport { .. })
            | ClientResponse::MissingSession
            | ClientResponse::SessionError
            | ClientResponse::PayloadTooLarge => Err(RequestError::Assertion),
            ClientResponse::DecodingError => Err(RequestError::Assertion),
            ClientResponse::Unavailable => Err(RequestError::Transient),
            ClientResponse::InvalidAuth => Err(RequestError::InvalidAuth),
            ClientResponse::RateLimitExceeded => Err(RequestError::RateLimitExceeded),
        }
    }

    #[instrument(
        level = "trace",
        skip(self, session, request),
        err(level = "trace", Debug)
    )]
    async fn make_transport_request(
        &self,
        realm: &Realm,
        session: &mut Session,
        request: &[u8],
    ) -> Result<Vec<u8>, RequestErrorOrMissingSession> {
        let auth_token = self
            .auth_token_manager
            .get(&realm.id)
            .await
            .ok_or(RequestError::InvalidAuth)?;

        match rpc::send(
            &self.http,
            &realm.address,
            ClientRequest {
                realm: realm.id,
                auth_token,
                session_id: session.session_id,
                kind: ClientRequestKind::SecretsRequest,
                encrypted: NoiseRequest::Transport {
                    ciphertext: session
                        .transport
                        .encrypt(request)
                        .map_err(|_| RequestError::Assertion)?,
                },
            },
        )
        .await
        .map_err(RequestError::from)?
        {
            ClientResponse::Ok(NoiseResponse::Transport { ciphertext }) => {
                session.last_used = Instant::now();
                Ok(session
                    .transport
                    .decrypt(ciphertext.as_slice())
                    .map_err(|_| RequestError::Assertion)?)
            }
            ClientResponse::Ok(NoiseResponse::Handshake { .. }) | ClientResponse::SessionError => {
                Err(RequestError::Assertion.into())
            }
            ClientResponse::DecodingError | ClientResponse::PayloadTooLarge => {
                Err(RequestError::Assertion.into())
            }
            ClientResponse::Unavailable => Err(RequestError::Transient.into()),
            ClientResponse::InvalidAuth => Err(RequestError::InvalidAuth.into()),
            ClientResponse::MissingSession => Err(RequestErrorOrMissingSession::MissingSession),
            ClientResponse::RateLimitExceeded => Err(RequestError::RateLimitExceeded.into()),
        }
    }

    async fn try_make_request(
        &self,
        realm: &Realm,
        public_key: &Vec<u8>,
        session: Option<Session>,
        request: &[u8],
        needs_forward_secrecy: NeedsForwardSecrecy,
    ) -> Result<(Session, Vec<u8>), RequestErrorOrMissingSession> {
        match session {
            None if needs_forward_secrecy.0 => {
                let (mut session, handshake_response) =
                    self.make_handshake_request(realm, public_key, &[]).await?;
                if !handshake_response.is_empty() {
                    return Err(RequestError::Assertion.into());
                }
                let response = self
                    .make_transport_request(realm, &mut session, request)
                    .await
                    .map_err(|e| match e {
                        RequestErrorOrMissingSession::RequestError(e) => e,
                        RequestErrorOrMissingSession::MissingSession => RequestError::Assertion,
                    })?;
                Ok((session, response))
            }

            None => {
                assert!(!needs_forward_secrecy.0);
                Ok(self
                    .make_handshake_request(realm, public_key, request)
                    .await?)
            }

            Some(mut session) => self
                .make_transport_request(realm, &mut session, request)
                .await
                .map(|response| (session, response)),
        }
    }

    pub(crate) async fn make_request(
        &self,
        realm: &Realm,
        request: SecretsRequest,
    ) -> Result<SecretsResponse, RequestError> {
        match &realm.public_key {
            Some(public_key) => {
                self.make_hardware_realm_request(realm, public_key, request)
                    .await
            }
            None => self.make_software_realm_request(realm, request).await,
        }
    }

    async fn make_software_realm_request(
        &self,
        realm: &Realm,
        request: SecretsRequest,
    ) -> Result<SecretsResponse, RequestError> {
        let auth_token = self
            .auth_token_manager
            .get(&realm.id)
            .await
            .ok_or(RequestError::InvalidAuth)?;

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", auth_token.expose_secret()),
        );

        for _attempt in 0..2 {
            return match rpc::send_with_options(
                &self.http,
                &realm.address,
                request.clone(),
                SendOptions::default().with_headers(headers.clone()),
            )
            .await
            .map_err(RequestError::from)
            {
                Ok(response) => Ok(response),
                Err(RequestError::Transient) => {
                    self.sleeper.sleep(Duration::from_millis(5)).await;
                    continue;
                }
                Err(e) => Err(e),
            };
        }
        Err(RequestError::Transient)
    }

    async fn make_hardware_realm_request(
        &self,
        realm: &Realm,
        public_key: &Vec<u8>,
        request: SecretsRequest,
    ) -> Result<SecretsResponse, RequestError> {
        let needs_forward_secrecy = NeedsForwardSecrecy(request.needs_forward_secrecy());
        let request = marshalling::to_vec(&request).map_err(|_| RequestError::Assertion)?;
        let mut locked = self.sessions.get(&realm.id).unwrap().lock().await;

        // The first iteration of this loop attempts the request with an
        // existing session, if available. Subsequent iterations always use a
        // new session. Even using a brand new session can result in a
        // `MissingSession` error, if the server restarts at an inopportune
        // time. This loop tries a few times, but beyond that, it's not likely
        // to succeed.
        for attempt in 1..6 {
            let session = locked
                .take()
                .filter(|session| session.last_used.elapsed() < session.lifetime);
            match self
                .try_make_request(realm, public_key, session, &request, needs_forward_secrecy)
                .await
            {
                Ok((session, response)) => {
                    *locked = Some(session);
                    std::mem::drop(locked);
                    let padded_response =
                        marshalling::from_slice::<PaddedSecretsResponse>(response.as_slice())
                            .map_err(|_| RequestError::Assertion)?;
                    return SecretsResponse::try_from(&padded_response)
                        .map_err(|_| RequestError::Assertion);
                }
                Err(RequestErrorOrMissingSession::RequestError(RequestError::Transient)) => {
                    // This could be due to an in progress leadership transfer, or other transitory problem.
                    // We can retry this as it'll likely need a new session anyway.
                    self.sleeper.sleep(Duration::from_millis(5 * attempt)).await;
                    continue;
                }
                Err(RequestErrorOrMissingSession::RequestError(e)) => return Err(e),
                Err(RequestErrorOrMissingSession::MissingSession) => {
                    // The next iteration will open a new session and
                    // should have a high chance of success.
                    continue;
                }
            }
        }
        Err(RequestError::Transient)
    }
}

/// Waits for all the futures to complete, unless enough fail that there is no
/// way for the threshold to be met.
///
/// Panics if the total number of `futures` given is less than the threshold,
/// or if the threshold is 0.
///
/// The results and errors are returned in no particular order. An `Ok` return
/// value will contain at least `threshold` results. An `Error` return value
/// will be the smallest error seen (using `Ord`).
pub(crate) async fn join_at_least_threshold<I, F, T, E>(
    futures: I,
    threshold: u32,
) -> Result<Vec<T>, E>
where
    I: IntoIterator<Item = F>,
    F: Future<Output = Result<T, E>>,
    E: Ord,
{
    let mut futures: FuturesUnordered<F> = futures.into_iter().collect();
    let total = futures.len();
    let threshold = threshold as usize;
    assert!(total >= threshold);
    assert!(threshold > 0);
    let mut oks = Vec::with_capacity(total);
    let mut errors = Vec::new();

    while let Some(result) = futures.next().await {
        match result {
            Ok(ok) => {
                oks.push(ok);
            }

            Err(error) => {
                errors.push(error);
                if errors.len() > total - threshold {
                    return Err(min(errors));
                }
            }
        }
    }

    assert!(oks.len() >= threshold);
    Ok(oks)
}

/// Consumes a `Vec` and returns its minimum value.
///
/// This is used for selecting the "best" error out of a set of errors.
fn min<T: Ord>(values: Vec<T>) -> T {
    values.into_iter().min().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::request::join_at_least_threshold;
    use futures::future::{err, ready};

    #[tokio::test]
    async fn test_join_at_least_threshold() {
        let futures = vec![
            ready(Ok("Result 1")),
            ready(Ok("Result 2")),
            ready(Ok("Result 3")),
            err(Box::new(TestError)),
            ready(Ok("Result 4")),
        ];

        let result: Result<Vec<&str>, Box<TestError>> = join_at_least_threshold(futures, 3).await;

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(
            results,
            vec!["Result 1", "Result 2", "Result 3", "Result 4"]
        );

        let futures = vec![
            err(Box::new(TestError)),
            err(Box::new(TestError)),
            err(Box::new(TestError)),
        ];

        let result: Result<Vec<&str>, Box<TestError>> = join_at_least_threshold(futures, 2).await;

        assert!(result.is_err());
    }

    #[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct TestError;
}
