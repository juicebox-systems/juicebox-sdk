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
    types::{CheckedConfiguration, TagGeneratingKey, TgkShare},
    Client, HashedPin, Pin, Realm, Sleeper, UserSecret,
};

/// Error return type for [`Client::recover`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum RecoverError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// The secret could not be unlocked, but you can try again
    /// with a different PIN if you have guesses remaining. If no
    /// guesses remain, this secret is locked and unaccessible.
    InvalidPin { guesses_remaining: u16 },

    /// The secret was not registered or not fully registered with the
    /// provided realms.
    NotRegistered,

    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient,

    /// A software error has occured. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software,
    /// updates and try again.
    Assertion,
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
    generation: GenerationNumber,
    retry: Option<GenerationNumber>,
}

/// Successful return type of [`Client::recover1`].
#[derive(Debug)]
struct Recover1Success {
    generation: GenerationNumber,
    tgk_share: TgkShare,
    previous_generation: Option<GenerationNumber>,
}

impl<S: Sleeper, Http: http::Client> Client<S, Http> {
    pub(crate) async fn recover_latest_registered_configuration(
        &self,
        pin: &Pin,
    ) -> Result<UserSecret, RecoverError> {
        let mut configuration = &self.configuration;
        let mut iter = self.previous_configurations.iter();
        loop {
            return match self
                .recover_latest_available_generation(pin, configuration)
                .await
            {
                Ok(secret) => Ok(secret),
                Err(RecoverError::NotRegistered) => {
                    if let Some(next_configuration) = iter.next() {
                        configuration = next_configuration;
                        continue;
                    }

                    Err(RecoverError::NotRegistered)
                }
                Err(err) => Err(err),
            };
        }
    }

    /// Recovers a PIN-protected secret from the latest agreed upon generation.
    pub(crate) async fn recover_latest_available_generation(
        &self,
        pin: &Pin,
        configuration: &CheckedConfiguration,
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

        loop {
            return match self
                .recover_generation(generation, &hashed_pin, configuration)
                .await
            {
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

                Err(RecoverGenError {
                    error,
                    generation: _,
                    retry,
                }) => {
                    if retry.is_some() {
                        assert!(retry < generation);
                        generation = retry;
                        continue;
                    }
                    Err(error)
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
        configuration: &CheckedConfiguration,
    ) -> Result<RecoverGenSuccess, RecoverGenError> {
        let recover1_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover1(realm, request_generation, hashed_pin));

        let mut generations_found = BTreeSet::new();
        let mut tgk_shares: Vec<(GenerationNumber, TgkShare)> = Vec::new();
        let mut found_errors: Vec<RecoverError> = Vec::new();
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

                Err(
                    e @ RecoverGenError {
                        error:
                            RecoverError::InvalidAuth
                            | RecoverError::Assertion
                            | RecoverError::Transient,
                        generation: _,
                        retry: _,
                    },
                ) => {
                    return Err(e);
                }

                Err(RecoverGenError {
                    error,
                    generation,
                    retry,
                }) => {
                    generations_found.insert(generation);
                    if let Some(generation) = retry {
                        generations_found.insert(generation);
                    }
                    found_errors.push(error);
                }
            }
        }

        let mut iter = generations_found.into_iter().rev();
        let current_generation = iter.next().unwrap();
        let previous_generation = iter.next();

        if !found_errors.is_empty() {
            let found_error = found_errors[0];
            let all_errors_equal = found_errors.iter().all(|e| *e == found_error);
            let all_realms_errored = found_errors.len() == configuration.realms.len();
            if all_errors_equal && all_realms_errored {
                return Err(RecoverGenError {
                    error: found_error,
                    generation: current_generation,
                    retry: previous_generation,
                });
            } else {
                return Err(RecoverGenError {
                    error: RecoverError::Assertion,
                    generation: current_generation,
                    retry: previous_generation,
                });
            }
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

        if tgk_shares.len() < usize::from(configuration.recover_threshold) {
            return Err(RecoverGenError {
                error: RecoverError::NotRegistered,
                generation: current_generation,
                retry: previous_generation,
            });
        }

        let tgk = match Sharks(configuration.recover_threshold).recover(&tgk_shares) {
            Ok(tgk) => TagGeneratingKey(tgk),

            Err(_) => {
                return Err(RecoverGenError {
                    error: RecoverError::Assertion,
                    generation: current_generation,
                    retry: previous_generation,
                });
            }
        };

        let recover2_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover2(realm, current_generation, tgk.tag(&realm.public_key)));

        let recover2_results = join_all(recover2_requests).await;

        let mut secret_shares = Vec::<sharks::Share>::new();
        for result in recover2_results {
            match result {
                Ok(secret_share) => match sharks::Share::try_from(secret_share.expose_secret()) {
                    Ok(secret_share) => {
                        secret_shares.push(secret_share);
                    }

                    Err(_) => {
                        return Err(RecoverGenError {
                            error: RecoverError::Assertion,
                            generation: current_generation,
                            retry: previous_generation,
                        })
                    }
                },

                Err(error) => {
                    return Err(RecoverGenError {
                        error,
                        generation: current_generation,
                        retry: previous_generation,
                    })
                }
            }
        }

        match Sharks(configuration.recover_threshold).recover(&secret_shares) {
            Ok(secret) => Ok(RecoverGenSuccess {
                generation: current_generation,
                secret: UserSecret::from(secret),
                found_earlier_generations: previous_generation.is_some(),
            }),

            Err(_) => Err(RecoverGenError {
                error: RecoverError::Transient,
                generation: current_generation,
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

        let current_generation = generation.unwrap_or(GenerationNumber(0));

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
            Err(RequestError::Transient) => {
                return Err(RecoverGenError {
                    error: RecoverError::Transient,
                    generation: current_generation,
                    retry: None,
                })
            }

            Err(RequestError::Assertion) => {
                return Err(RecoverGenError {
                    error: RecoverError::Assertion,
                    generation: current_generation,
                    retry: None,
                })
            }

            Err(RequestError::InvalidAuth) => {
                return Err(RecoverGenError {
                    error: RecoverError::InvalidAuth,
                    generation: current_generation,
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
                        error: RecoverError::NotRegistered,
                        generation: generation.unwrap_or(GenerationNumber(0)),
                        retry: previous_generation,
                    });
                }

                Recover1Response::PartiallyRegistered {
                    generation,
                    previous_generation,
                    ..
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::NotRegistered,
                        generation,
                        retry: previous_generation,
                    });
                }

                Recover1Response::NoGuesses {
                    generation,
                    previous_generation,
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::InvalidPin {
                            guesses_remaining: 0,
                        },
                        generation,
                        retry: previous_generation,
                    });
                }
            },

            Ok(_) => {
                return Err(RecoverGenError {
                    error: RecoverError::Assertion,
                    generation: current_generation,
                    retry: None,
                })
            }
        };

        let oprf_pin = blinded_pin
            .state
            .finalize(hashed_pin.expose_secret(), &blinded_oprf_pin)
            .map_err(|e| {
                println!("failed to unblind oprf result: {e:?}");
                RecoverGenError {
                    error: RecoverError::Transient,
                    generation,
                    retry: previous_generation,
                }
            })?;

        let tgk_share = TgkShare::try_from_masked(&masked_tgk_share, &oprf_pin).map_err(|_| {
            RecoverGenError {
                error: RecoverError::Transient,
                generation,
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
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok(secret_share) => Ok(secret_share),
                Recover2Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover2Response::BadUnlockTag { guesses_remaining } => {
                    Err(RecoverError::InvalidPin { guesses_remaining })
                }
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }
}
