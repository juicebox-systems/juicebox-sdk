use futures::future::{join_all, try_join_all};
use rand::rngs::OsRng;
use sharks::Sharks;
use std::iter::zip;
use tracing::instrument;

use loam_sdk_core::{
    requests::{
        Register1Request, Register1Response, Register2Request, Register2Response, SecretsRequest,
        SecretsResponse,
    },
    types::{GenerationNumber, OprfClient, OprfResult, UnlockTag, UserSecretShare},
};

use crate::{
    http,
    request::RequestError,
    types::{oprf_output_size, TagGeneratingKey, TgkShare},
    Client, HashedPin, Pin, Policy, Realm, Sleeper, UserSecret,
};

/// Error return type for [`Client::register`].
#[derive(Debug)]
pub enum RegisterError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient,

    /// A software error has occured. This request should not be retried
    /// with the same parameters. Verify your inputs and try again.
    Assertion,
}

/// Successful return type of [`Client::register_generation`].
#[derive(Debug)]
struct RegisterGenSuccess {
    /// If true, at least one generation record with a lower generation number
    /// was found on the server. The client should attempt to delete those
    /// records.
    found_earlier_generations: bool,
}

/// Error return type of [`Client::register_generation`].
#[derive(Debug)]
enum RegisterGenError {
    Error(RegisterError),
    Retry(GenerationNumber),
}

/// Named arguments to [`Client::register2`].
struct Register2Args {
    generation: GenerationNumber,
    oprf_pin: OprfResult,
    tgk_share: TgkShare,
    tag: UnlockTag,
    secret_share: UserSecretShare,
    policy: Policy,
}

impl<S: Sleeper, Http: http::Client> Client<S, Http> {
    /// Registers a PIN-protected secret at the first available generation number.
    pub(crate) async fn register_first_available_generation(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        let hashed_pin = pin
            .hash(&self.configuration.pin_hashing_mode, &self.auth_token)
            .expect("pin hashing error");

        // This first tries to register generation 0. If that generation has
        // already been used, it then tries to register the first generation
        // that was available on all servers.
        match self
            .register_generation(GenerationNumber(0), &hashed_pin, secret, policy.clone())
            .await
        {
            Ok(_) => Ok(()),

            Err(RegisterGenError::Error(e)) => Err(e),

            Err(RegisterGenError::Retry(generation)) => {
                match self
                    .register_generation(generation, &hashed_pin, secret, policy)
                    .await
                {
                    Ok(RegisterGenSuccess {
                        found_earlier_generations,
                    }) => {
                        if found_earlier_generations {
                            if let Err(delete_err) = self.delete_up_to(Some(generation)).await {
                                println!("client: warning: register failed to clean up earlier registrations: {delete_err:?}");
                            }
                        }
                        Ok(())
                    }

                    Err(RegisterGenError::Error(e)) => Err(e),

                    Err(RegisterGenError::Retry(_)) => Err(RegisterError::Assertion),
                }
            }
        }
    }

    /// Registers a PIN-protected secret at a given generation number.
    async fn register_generation(
        &self,
        generation: GenerationNumber,
        hashed_pin: &HashedPin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<RegisterGenSuccess, RegisterGenError> {
        let register1_requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.register1(realm, generation, hashed_pin));

        // Wait for and process the results to `register1` from all the servers
        // here. It's technically possible to have all the servers do both
        // phases of registration without any synchronization. However, in the
        // event that the desired `generation` is unavailable on some server,
        // powering through to phase 2 would waste server time and leave behind
        // cruft. It's better to synchronize here and abort early instead.
        let oprfs_pin: Vec<Option<OprfResult>> = {
            let mut oprfs_pin = Vec::with_capacity(self.configuration.realms.len());
            // The next generation number that is available on every server (so
            // far).
            let mut retry_generation = None;
            let mut network_errors = 0;
            for result in join_all(register1_requests).await {
                match result {
                    Ok(oprf_pin) => {
                        oprfs_pin.push(Some(oprf_pin));
                    }
                    Err(RegisterGenError::Error(e @ RegisterError::Transient)) => {
                        println!("client: warning: transient error during register1: {e:?}");
                        network_errors += 1;
                        if self.configuration.realms.len() - network_errors
                            < usize::from(self.configuration.register_threshold)
                        {
                            return Err(RegisterGenError::Error(e));
                        }
                        oprfs_pin.push(None);
                    }
                    Err(e @ RegisterGenError::Error(_)) => return Err(e),
                    Err(RegisterGenError::Retry(generation)) => match retry_generation {
                        None => retry_generation = Some(generation),
                        Some(g) => {
                            if g < generation {
                                retry_generation = Some(generation);
                            }
                        }
                    },
                }
            }
            if let Some(g) = retry_generation {
                return Err(RegisterGenError::Retry(g));
            }
            assert_eq!(oprfs_pin.len(), self.configuration.realms.len());
            oprfs_pin
        };

        let tgk = TagGeneratingKey::new_random();

        let tgk_shares: Vec<TgkShare> = {
            Sharks(self.configuration.recover_threshold)
                .dealer_rng(&tgk.0, &mut OsRng)
                .take(self.configuration.realms.len())
                .map(TgkShare)
                .collect()
        };

        let secret_shares: Vec<UserSecretShare> = {
            Sharks(self.configuration.recover_threshold)
                .dealer_rng(secret.expose_secret(), &mut OsRng)
                .take(self.configuration.realms.len())
                .map(|share| UserSecretShare::from(Vec::<u8>::from(&share)))
                .collect()
        };

        let register2_requests = zip4(
            &self.configuration.realms,
            oprfs_pin,
            tgk_shares,
            secret_shares,
        )
        .filter_map(|(realm, oprf_pin, tgk_share, secret_share)| {
            oprf_pin.map(|oprf_pin| {
                self.register2(
                    realm,
                    Register2Args {
                        generation,
                        oprf_pin,
                        tgk_share,
                        tag: tgk.tag(&realm.public_key),
                        secret_share,
                        policy: policy.clone(),
                    },
                )
            })
        });

        match try_join_all(register2_requests).await {
            Ok(success) => Ok(RegisterGenSuccess {
                found_earlier_generations: success.iter().any(|s| s.found_earlier_generations),
            }),
            Err(e) => Err(RegisterGenError::Error(e)),
        }
    }

    /// Executes phase 1 of registration on a particular realm at a particular
    /// generation.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn register1(
        &self,
        realm: &Realm,
        generation: GenerationNumber,
        hashed_pin: &HashedPin,
    ) -> Result<OprfResult, RegisterGenError> {
        let blinded_pin = OprfClient::blind(hashed_pin.expose_secret(), &mut OsRng)
            .expect("voprf blinding error");

        let register1_request = self.make_request(
            realm,
            SecretsRequest::Register1(Register1Request {
                generation,
                blinded_pin: blinded_pin.message,
            }),
        );
        match register1_request.await {
            Err(RequestError::Network) => Err(RegisterGenError::Error(RegisterError::Transient)),
            Err(RequestError::Deserialization(_) | RequestError::Serialization(_)) => {
                Err(RegisterGenError::Error(RegisterError::Transient))
            }
            Err(RequestError::HttpStatus(_status)) => {
                Err(RegisterGenError::Error(RegisterError::Transient))
            }
            Err(RequestError::Session) => Err(RegisterGenError::Error(RegisterError::Transient)),
            Err(RequestError::Decoding) => Err(RegisterGenError::Error(RegisterError::Assertion)),
            Err(RequestError::Unavailable) => {
                Err(RegisterGenError::Error(RegisterError::Transient))
            }
            Err(RequestError::InvalidAuth) => {
                Err(RegisterGenError::Error(RegisterError::InvalidAuth))
            }

            Ok(SecretsResponse::Register1(rr)) => match rr {
                Register1Response::Ok { blinded_oprf_pin } => {
                    let oprf_pin = blinded_pin
                        .state
                        .finalize(hashed_pin.expose_secret(), &blinded_oprf_pin)
                        .map_err(|e| {
                            println!("failed to unblind oprf result: {e:?}");
                            RegisterGenError::Error(RegisterError::Assertion)
                        })?;
                    if oprf_pin.len() != oprf_output_size() {
                        return Err(RegisterGenError::Error(RegisterError::Assertion));
                    }
                    Ok(OprfResult(oprf_pin))
                }

                Register1Response::BadGeneration { first_available } => {
                    Err(RegisterGenError::Retry(first_available))
                }
            },

            Ok(_) => Err(RegisterGenError::Error(RegisterError::Assertion)),
        }
    }

    /// Executes phase 2 of registration on a particular realm at a particular
    /// generation.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn register2(
        &self,
        realm: &Realm,
        Register2Args {
            generation,
            oprf_pin,
            tgk_share,
            tag,
            secret_share,
            policy,
        }: Register2Args,
    ) -> Result<RegisterGenSuccess, RegisterError> {
        let masked_tgk_share = tgk_share.mask(&oprf_pin);

        let register2_request = self.make_request(
            realm,
            SecretsRequest::Register2(Register2Request {
                generation,
                masked_tgk_share,
                tag,
                secret_share,
                policy,
            }),
        );

        match register2_request.await {
            Err(RequestError::Network) => Err(RegisterError::Transient),
            Err(RequestError::Deserialization(_) | RequestError::Serialization(_)) => {
                Err(RegisterError::Transient)
            }
            Err(RequestError::HttpStatus(_status)) => Err(RegisterError::Transient),
            Err(RequestError::Session) => Err(RegisterError::Transient),
            Err(RequestError::Decoding) => Err(RegisterError::Assertion),
            Err(RequestError::Unavailable) => Err(RegisterError::Transient),
            Err(RequestError::InvalidAuth) => Err(RegisterError::InvalidAuth),

            Ok(SecretsResponse::Register2(rr)) => match rr {
                Register2Response::Ok {
                    found_earlier_generations,
                } => Ok(RegisterGenSuccess {
                    found_earlier_generations,
                }),
                Register2Response::NotRegistering | Register2Response::AlreadyRegistered => {
                    Err(RegisterError::Assertion)
                }
            },
            Ok(_) => Err(RegisterError::Assertion),
        }
    }
}

fn zip4<A, B, C, D>(
    a: A,
    b: B,
    c: C,
    d: D,
) -> impl Iterator<Item = (A::Item, B::Item, C::Item, D::Item)>
where
    A: IntoIterator,
    B: IntoIterator,
    C: IntoIterator,
    D: IntoIterator,
{
    zip(zip(a, b), zip(c, d)).map(|((a, b), (c, d))| (a, b, c, d))
}
