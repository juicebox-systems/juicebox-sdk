use futures::future::join_all;
use rand::rngs::OsRng;
use sharks::Sharks;
use std::collections::BTreeSet;
use tracing::instrument;

use loam_sdk_core::{
    requests::{
        Recover1Request, Recover1Response, Recover2Request, Recover2Response, SecretsRequest,
        SecretsResponse,
    },
    types::{
        GenerationNumber, MaskedTgkShare, OprfBlindedResult, OprfClient, UnlockTag, UserSecretShare,
    },
};

use crate::{
    http,
    request::RequestError,
    types::{TagGeneratingKey, TgkShare},
    Client, HashedPin, Pin, Realm, UserSecret,
};

/// Error return type for [`Client::recover`].
#[derive(Debug)]
pub enum RecoverError {
    /// A transient error in sending or receiving requests to a realm.
    NetworkError,

    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    // TODO: Figure out a clean way to surface unsuccessful details to clients
    // without externally exposing implementation details like `GenerationNumber`
    /// A list of attempts explaining why the recovery failed.
    ///
    /// Each entry in the vector corresponds to an attempt at recovery with
    /// a particular realm at a particular generation number.
    Unsuccessful(Vec<(GenerationNumber, UnsuccessfulRecoverReason)>),

    ProtocolError,
}

/// An explanation for a [`RecoverError::Unsuccessful`] entry.
#[derive(Debug)]
pub enum UnsuccessfulRecoverReason {
    /// The secret was not registered or not fully registered.
    NotRegistered,

    /// The secret was locked due to too many failed recovery attempts.
    NoGuesses,

    /// The secret could not be unlocked, most likely due to an incorrect PIN.
    FailedUnlock,

    /// An error representing an assumption was not met in executing the
    /// registration protocol.
    ///
    /// This can arise if any servers are misbehaving or running an unexpected
    /// version of the protocol, or if the user is concurrently executing
    /// requests or has previously executed requests with a misbehaving client.
    ProtocolError,
}

/// Successful return type of [`Client::recover_generation`].
struct RecoverGenSuccess {
    generation: GenerationNumber,
    secret: UserSecret,
    found_earlier_generations: bool,
}

/// Error return type of [`Client::recover_generation`].
#[derive(Debug)]
struct RecoverGenError {
    error: RecoverError,
    retry: Option<GenerationNumber>,
}

/// Successful return type of [`Client::recover1`].
#[derive(Debug)]
struct Recover1Success {
    generation: GenerationNumber,
    tgk_share: TgkShare,
    previous_generation: Option<GenerationNumber>,
}

impl<Http: http::Client> Client<Http> {
    /// Recovers a PIN-protected secret from the latest agreed upon generation.
    pub(crate) async fn recover_latest_available_generation(
        &self,
        pin: &Pin,
    ) -> Result<UserSecret, RecoverError> {
        let hashed_pin = pin
            .hash(&self.configuration.pin_hashing_mode, &self.auth_token)
            .expect("pin hashing error");

        // First, try the latest generation on each server (represented as
        // `generation = None`). In the common case, all the servers will
        // agree on the last registered generation. If they don't, step back by
        // one generation at a time, limited to actual generations seen,
        // heading towards generation 0.

        let mut generation: Option<GenerationNumber> = None;
        let mut unsuccessful: Vec<(GenerationNumber, UnsuccessfulRecoverReason)> = Vec::new();

        loop {
            return match self.recover_generation(generation, &hashed_pin).await {
                Ok(RecoverGenSuccess {
                    generation,
                    secret,
                    found_earlier_generations,
                }) => {
                    if found_earlier_generations {
                        if let Err(delete_err) = self.delete_up_to(Some(generation)).await {
                            println!("client: warning: recover failed to clean up earlier registrations: {delete_err:?}");
                        }
                    }
                    Ok(secret)
                }

                Err(
                    e @ RecoverGenError {
                        error:
                            RecoverError::NetworkError
                            | RecoverError::InvalidAuth
                            | RecoverError::ProtocolError,
                        retry: _,
                    },
                ) => Err(e.error),

                Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(detail),
                    retry,
                }) => {
                    unsuccessful.extend(detail);
                    if retry.is_some() {
                        assert!(retry < generation);
                        generation = retry;
                        continue;
                    }
                    Err(RecoverError::Unsuccessful(unsuccessful))
                }
            };
        }
    }

    /// Retrieves a PIN-protected secret at a given generation number.
    ///
    /// If the generation number is given as `None`, tries the latest
    /// generation present on each realm.
    async fn recover_generation(
        &self,
        request_generation: Option<GenerationNumber>,
        hashed_pin: &HashedPin,
    ) -> Result<RecoverGenSuccess, RecoverGenError> {
        let recover1_requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.recover1(realm, request_generation, hashed_pin));

        let mut generations_found = BTreeSet::new();
        let mut tgk_shares: Vec<(GenerationNumber, TgkShare)> = Vec::new();
        let mut unsuccessful: Vec<(GenerationNumber, UnsuccessfulRecoverReason)> = Vec::new();
        for result in join_all(recover1_requests).await {
            match result {
                Ok(Recover1Success {
                    generation,
                    tgk_share,
                    previous_generation,
                }) => {
                    generations_found.insert(generation);
                    if let Some(p) = previous_generation {
                        generations_found.insert(p);
                    }
                    tgk_shares.push((generation, tgk_share));
                }

                Err(RecoverGenError {
                    error: error @ RecoverError::NetworkError,
                    retry: _,
                }) => {
                    println!("client: warning: transient error during recover1: {error:?}");
                }

                Err(
                    e @ RecoverGenError {
                        error: RecoverError::InvalidAuth | RecoverError::ProtocolError,
                        retry: _,
                    },
                ) => {
                    return Err(e);
                }

                Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(detail),
                    retry,
                }) => {
                    for (generation, _reason) in &detail {
                        generations_found.insert(*generation);
                    }
                    unsuccessful.extend(detail);
                    if let Some(generation) = retry {
                        generations_found.insert(generation);
                    }
                }
            }
        }

        let mut iter = generations_found.into_iter().rev();
        let current_generation = iter.next().unwrap();
        let previous_generation = iter.next();

        if !unsuccessful.is_empty() {
            return Err(RecoverGenError {
                error: RecoverError::Unsuccessful(unsuccessful),
                retry: previous_generation,
            });
        }

        // At this point, we know the phase 1 requests were successful on each
        // realm for some generation, but their generations may not have
        // agreed.

        let tgk_shares: Vec<sharks::Share> = tgk_shares
            .into_iter()
            .filter_map(|(generation, share)| {
                if generation == current_generation {
                    Some(share.0)
                } else {
                    None
                }
            })
            .collect();

        if tgk_shares.len() < usize::from(self.configuration.recover_threshold) {
            return Err(RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    current_generation,
                    UnsuccessfulRecoverReason::NotRegistered,
                )]),
                retry: previous_generation,
            });
        }

        let tgk = match Sharks(self.configuration.recover_threshold).recover(&tgk_shares) {
            Ok(tgk) => TagGeneratingKey(tgk),

            Err(_) => {
                return Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(vec![(
                        current_generation,
                        UnsuccessfulRecoverReason::ProtocolError,
                    )]),
                    retry: previous_generation,
                });
            }
        };

        let recover2_requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.recover2(realm, current_generation, tgk.tag(&realm.public_key)));

        let recover2_results = join_all(recover2_requests).await;

        let mut secret_shares = Vec::<sharks::Share>::new();
        for result in recover2_results {
            match result {
                Ok(secret_share) => {
                    match sharks::Share::try_from(secret_share.expose_secret().as_slice()) {
                        Ok(secret_share) => {
                            secret_shares.push(secret_share);
                        }

                        Err(_) => {
                            return Err(RecoverGenError {
                                error: RecoverError::Unsuccessful(vec![(
                                    current_generation,
                                    UnsuccessfulRecoverReason::ProtocolError,
                                )]),
                                retry: previous_generation,
                            })
                        }
                    }
                }

                Err(error @ RecoverError::NetworkError) => {
                    println!("client: warning: transient error during recover2: {error:?}");
                }

                Err(error) => {
                    return Err(RecoverGenError {
                        error,
                        retry: previous_generation,
                    })
                }
            }
        }

        match Sharks(self.configuration.recover_threshold).recover(&secret_shares) {
            Ok(secret) => Ok(RecoverGenSuccess {
                generation: current_generation,
                secret: UserSecret::from(secret),
                found_earlier_generations: previous_generation.is_some(),
            }),

            Err(_) => Err(RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    current_generation,
                    UnsuccessfulRecoverReason::ProtocolError,
                )]),
                retry: previous_generation,
            }),
        }
    }

    /// Executes phase 1 of recovery on a particular realm at a particular
    /// generation.
    ///
    /// If the generation number is given as `None`, tries the latest
    /// generation present on the realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover1(
        &self,
        realm: &Realm,
        generation: Option<GenerationNumber>,
        hashed_pin: &HashedPin,
    ) -> Result<Recover1Success, RecoverGenError> {
        let blinded_pin = OprfClient::blind(hashed_pin.expose_secret(), &mut OsRng)
            .expect("voprf blinding error");

        let recover1_request = self.make_request(
            realm,
            SecretsRequest::Recover1(Recover1Request {
                generation,
                blinded_pin: blinded_pin.message,
            }),
        );

        // This is a verbose way to copy some fields out to this outer scope.
        // It helps avoid having to process these fields at a high level of
        // indentation.
        struct OkResponse {
            generation: GenerationNumber,
            blinded_oprf_pin: OprfBlindedResult,
            masked_tgk_share: MaskedTgkShare,
            previous_generation: Option<GenerationNumber>,
        }
        let OkResponse {
            generation,
            blinded_oprf_pin,
            masked_tgk_share,
            previous_generation,
        } = match recover1_request.await {
            Err(RequestError::Network) => {
                return Err(RecoverGenError {
                    error: RecoverError::NetworkError,
                    retry: None,
                })
            }
            Err(RequestError::Deserialization(_) | RequestError::Serialization(_)) => {
                return Err(RecoverGenError {
                    error: RecoverError::ProtocolError,
                    retry: None,
                })
            }
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Session) => todo!(),
            Err(RequestError::Decoding) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => {
                return Err(RecoverGenError {
                    error: RecoverError::InvalidAuth,
                    retry: None,
                })
            }

            Ok(SecretsResponse::Recover1(rr)) => match rr {
                Recover1Response::Ok {
                    generation,
                    blinded_oprf_pin,
                    masked_tgk_share,
                    previous_generation,
                } => OkResponse {
                    generation,
                    blinded_oprf_pin,
                    masked_tgk_share,
                    previous_generation,
                },

                Recover1Response::NotRegistered {
                    generation,
                    previous_generation,
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::Unsuccessful(vec![(
                            generation.unwrap_or(GenerationNumber(0)),
                            UnsuccessfulRecoverReason::NotRegistered,
                        )]),
                        retry: previous_generation,
                    });
                }

                Recover1Response::PartiallyRegistered {
                    generation,
                    previous_generation,
                    ..
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::Unsuccessful(vec![(
                            generation,
                            UnsuccessfulRecoverReason::NotRegistered,
                        )]),
                        retry: previous_generation,
                    });
                }

                Recover1Response::NoGuesses {
                    generation,
                    previous_generation,
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::Unsuccessful(vec![(
                            generation,
                            UnsuccessfulRecoverReason::NoGuesses,
                        )]),
                        retry: previous_generation,
                    });
                }
            },

            Ok(_) => todo!(),
        };

        let oprf_pin = blinded_pin
            .state
            .finalize(hashed_pin.expose_secret(), &blinded_oprf_pin)
            .map_err(|e| {
                println!("failed to unblind oprf result: {e:?}");
                RecoverGenError {
                    error: RecoverError::Unsuccessful(vec![(
                        generation,
                        UnsuccessfulRecoverReason::ProtocolError,
                    )]),
                    retry: previous_generation,
                }
            })?;

        let tgk_share = TgkShare::try_from_masked(&masked_tgk_share, &oprf_pin).map_err(|_| {
            RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::ProtocolError,
                )]),
                retry: previous_generation,
            }
        })?;

        Ok(Recover1Success {
            generation,
            tgk_share,
            previous_generation,
        })
    }

    /// Executes phase 2 of recovery on a particular realm at a particular
    /// generation.
    #[instrument(level = "trace", skip(self))]
    async fn recover2(
        &self,
        realm: &Realm,
        generation: GenerationNumber,
        tag: UnlockTag,
    ) -> Result<UserSecretShare, RecoverError> {
        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request { generation, tag }),
        );

        match recover2_request.await {
            Err(RequestError::Network) => Err(RecoverError::NetworkError),
            Err(RequestError::Deserialization(_) | RequestError::Serialization(_)) => {
                Err(RecoverError::ProtocolError)
            }
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Session) => todo!(),
            Err(RequestError::Decoding) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok(secret_share) => Ok(secret_share),
                Recover2Response::NotRegistered => Err(RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::NotRegistered,
                )])),
                Recover2Response::BadUnlockTag => Err(RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::FailedUnlock,
                )])),
            },
            Ok(_) => todo!(),
        }
    }
}
