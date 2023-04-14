use instant::Instant;
use rand::{rngs::OsRng, RngCore};
use x25519_dalek as x25519;

use crate::{http, types::Session, Client, Realm};
use loam_sdk_core::{
    marshalling,
    requests::{
        ClientRequest, ClientRequestKind, ClientResponse, NoiseRequest, NoiseResponse,
        SecretsRequest, SecretsResponse,
    },
    types::SessionId,
};
use loam_sdk_networking::rpc::{self, RpcError};
use loam_sdk_noise::client as noise;

pub(crate) enum RequestError {
    /// See [`RpcError::Network`].
    Network,
    /// See [`RpcError::HttpStatus`].
    HttpStatus(u16),
    /// Local errors serializing an outer or encapsulated request.
    Serialization(marshalling::SerializationError),
    /// Local errors deserializing an outer or encapsulated response.
    Deserialization(marshalling::DeserializationError),
    /// See [`ClientResponse::Unavailable`].
    Unavailable,
    /// See [`ClientResponse::InvalidAuth`].
    InvalidAuth,
    /// Local or remote errors with encrypting/decrypting Noise sessions,
    /// including [`ClientResponse::SessionError`].
    Session,
    /// See [`ClientResponse::DecodingError`].
    Decoding,
}

impl From<RpcError> for RequestError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::Network => Self::Network,
            RpcError::HttpStatus(s) => Self::HttpStatus(s),
            RpcError::Serialization(e) => Self::Serialization(e),
            RpcError::Deserialization(e) => Self::Deserialization(e),
        }
    }
}

/// Error type for [`Client::make_transport_request`].
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

impl<Http: http::Client> Client<Http> {
    async fn make_handshake_request(
        &self,
        realm: &Realm,
        request: &[u8],
    ) -> Result<(Session, Vec<u8>), RequestError> {
        let realm_public_key = {
            // Whether the public key looks valid is checked with the
            // `Configuration`, so it's OK to panic on that here.
            assert_eq!(realm.public_key.len(), 32);
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&realm.public_key);
            x25519::PublicKey::from(buf)
        };
        let (handshake, fields) = noise::Handshake::start(&realm_public_key, request, &mut OsRng)
            .map_err(|_| RequestError::Session)?;
        let session_id = SessionId(OsRng.next_u32());

        match rpc::send(
            &self.http,
            &realm.address,
            ClientRequest {
                realm: realm.id,
                auth_token: self.auth_token.clone(),
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
                    .map_err(|_| RequestError::Session)?;
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
            | ClientResponse::SessionError => Err(RequestError::Session),
            ClientResponse::DecodingError => Err(RequestError::Decoding),
            ClientResponse::Unavailable => Err(RequestError::Unavailable),
            ClientResponse::InvalidAuth => Err(RequestError::InvalidAuth),
        }
    }

    async fn make_transport_request(
        &self,
        realm: &Realm,
        session: &mut Session,
        request: &[u8],
    ) -> Result<Vec<u8>, RequestErrorOrMissingSession> {
        match rpc::send(
            &self.http,
            &realm.address,
            ClientRequest {
                realm: realm.id,
                auth_token: self.auth_token.clone(),
                session_id: session.session_id,
                kind: ClientRequestKind::SecretsRequest,
                encrypted: NoiseRequest::Transport {
                    ciphertext: session
                        .transport
                        .encrypt(request)
                        .map_err(|_| RequestError::Session)?,
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
                    .map_err(|_| RequestError::Session)?)
            }
            ClientResponse::Ok(NoiseResponse::Handshake { .. }) | ClientResponse::SessionError => {
                Err(RequestError::Session.into())
            }
            ClientResponse::DecodingError => Err(RequestError::Decoding.into()),
            ClientResponse::Unavailable => Err(RequestError::Unavailable.into()),
            ClientResponse::InvalidAuth => Err(RequestError::InvalidAuth.into()),
            ClientResponse::MissingSession => Err(RequestErrorOrMissingSession::MissingSession),
        }
    }

    async fn try_make_request(
        &self,
        realm: &Realm,
        session: Option<Session>,
        request: &[u8],
        needs_forward_secrecy: NeedsForwardSecrecy,
    ) -> Result<(Session, Vec<u8>), RequestErrorOrMissingSession> {
        match session {
            None if needs_forward_secrecy.0 => {
                let (mut session, handshake_response) =
                    self.make_handshake_request(realm, &[]).await?;
                if !handshake_response.is_empty() {
                    return Err(RequestError::Session.into());
                }
                let response = self
                    .make_transport_request(realm, &mut session, request)
                    .await
                    .map_err(|e| match e {
                        RequestErrorOrMissingSession::RequestError(e) => e,
                        RequestErrorOrMissingSession::MissingSession => RequestError::Session,
                    })?;
                Ok((session, response))
            }

            None => {
                assert!(!needs_forward_secrecy.0);
                Ok(self.make_handshake_request(realm, request).await?)
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
        let needs_forward_secrecy = NeedsForwardSecrecy(request.needs_forward_secrecy());
        let request = marshalling::to_vec(&request).map_err(RequestError::Serialization)?;
        // TODO: should we add some padding to the requests? and their responses?
        let mut locked = self.sessions.get(&realm.id).unwrap().lock().await;

        // The first iteration of this loop attempts the request with an
        // existing session, if available. Subsequent iterations always use a
        // new session. Even using a brand new session can result in a
        // `MissingSession` error, if the server restarts at an inopportune
        // time. This loop tries a few times, but beyond that, it's not likely
        // to succeed.
        for _attempt in 0..3 {
            let session = locked
                .take()
                .filter(|session| session.last_used.elapsed() < session.lifetime);
            match self
                .try_make_request(realm, session, &request, needs_forward_secrecy)
                .await
            {
                Ok((session, response)) => {
                    *locked = Some(session);
                    std::mem::drop(locked);
                    return marshalling::from_slice::<SecretsResponse>(response.as_slice())
                        .map_err(RequestError::Deserialization);
                }
                Err(RequestErrorOrMissingSession::RequestError(e)) => return Err(e),
                Err(RequestErrorOrMissingSession::MissingSession) => {
                    // The next iteration will open a new session and
                    // should have a high chance of success.
                    continue;
                }
            }
        }
        Err(RequestError::Session)
    }
}
