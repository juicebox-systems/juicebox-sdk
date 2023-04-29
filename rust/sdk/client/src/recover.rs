use futures::future::join_all;
use rand::rngs::OsRng;
use sharks::Sharks;
use subtle::ConstantTimeEq;
use tracing::instrument;

use loam_sdk_core::{
    requests::{
        Recover1Response, Recover2Request, Recover2Response, Recover3Request, Recover3Response,
        SecretsRequest, SecretsResponse,
    },
    types::{MaskedTgkShare, OprfBlindedResult, OprfClient, Salt, UnlockTag, UserSecretShare},
};

use crate::{
    http,
    pin::HashedPin,
    request::RequestError,
    types::{CheckedConfiguration, TagGeneratingKey, TgkShare},
    Client, Pin, Realm, Sleeper, UserSecret,
};

/// Error return type for [`Client::recover`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoverError {
    /// The secret could not be unlocked, but you can try again
    /// with a different PIN if you have guesses remaining. If no
    /// guesses remain, this secret is locked and inaccessible.
    InvalidPin { guesses_remaining: u16 },

    /// The secret was not registered or not fully registered with the
    /// provided realms.
    NotRegistered,

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

impl<S: Sleeper, Http: http::Client> Client<S, Http> {
    pub(crate) async fn perform_recover(&self, pin: &Pin) -> Result<UserSecret, RecoverError> {
        let mut configuration = &self.configuration;
        let mut iter = self.previous_configurations.iter();
        loop {
            return match self
                .perform_recover_with_configuration(pin, configuration)
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

    /// Recovers a PIN-protected secret.
    async fn perform_recover_with_configuration(
        &self,
        pin: &Pin,
        configuration: &CheckedConfiguration,
    ) -> Result<UserSecret, RecoverError> {
        let recover1_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover1(realm));

        let mut salt: Option<Salt> = None;

        let mut found_errors: Vec<RecoverError> = Vec::new();
        for result in join_all(recover1_requests).await {
            match result {
                Ok(new_salt) => {
                    if let Some(salt) = &salt {
                        if !bool::from(new_salt.ct_eq(salt)) {
                            return Err(RecoverError::Assertion);
                        }
                    } else {
                        salt = Some(new_salt);
                    }
                }
                Err(e) => self.collect_recover_error(&mut found_errors, e, configuration)?,
            }
        }

        let hashed_pin = pin
            .hash(&configuration.pin_hashing_mode, &salt.unwrap())
            .ok_or(RecoverError::Assertion)?;

        let recover2_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover2(realm, &hashed_pin));

        let mut tgk_shares: Vec<sharks::Share> = Vec::new();
        let mut found_errors: Vec<RecoverError> = Vec::new();
        for result in join_all(recover2_requests).await {
            match result {
                Ok(tgk_share) => {
                    tgk_shares.push(tgk_share.0);
                }

                Err(e) => self.collect_recover_error(&mut found_errors, e, configuration)?,
            }
        }

        if tgk_shares.len() < usize::from(configuration.recover_threshold) {
            return Err(RecoverError::NotRegistered);
        }

        let tgk = match Sharks(configuration.recover_threshold).recover(&tgk_shares) {
            Ok(tgk) => TagGeneratingKey::from(tgk),

            Err(_) => {
                return Err(RecoverError::Assertion);
            }
        };

        let recover3_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover3(realm, tgk.tag(&realm.public_key)));

        let recover3_results = join_all(recover3_requests).await;

        let mut secret_shares = Vec::<sharks::Share>::new();
        for result in recover3_results {
            match result {
                Ok(secret_share) => match sharks::Share::try_from(secret_share.expose_secret()) {
                    Ok(secret_share) => {
                        secret_shares.push(secret_share);
                    }

                    Err(_) => return Err(RecoverError::Assertion),
                },

                Err(error) => {
                    return Err(error);
                }
            }
        }

        match Sharks(configuration.recover_threshold).recover(&secret_shares) {
            Ok(secret) => Ok(UserSecret::from(secret)),
            Err(_) => Err(RecoverError::Assertion),
        }
    }

    /// Append errors into an error collection. If the number of errors exceeds the
    /// recover threshold for the configuration, return the highest priority error.
    fn collect_recover_error(
        &self,
        errors: &mut Vec<RecoverError>,
        error: RecoverError,
        configuration: &CheckedConfiguration,
    ) -> Result<(), RecoverError> {
        errors.push(error);

        if configuration.realms.len() - errors.len() < usize::from(configuration.recover_threshold)
        {
            errors.sort_unstable();
            return Err(errors[0]);
        }

        Ok(())
    }

    /// Executes phase 1 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover1(&self, realm: &Realm) -> Result<Salt, RecoverError> {
        match self.make_request(realm, SecretsRequest::Recover1).await {
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Ok(SecretsResponse::Recover1(response)) => match response {
                Recover1Response::Ok { salt } => Ok(salt),
                Recover1Response::NotRegistered => Err(RecoverError::NotRegistered),
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }

    /// Executes phase 2 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover2(
        &self,
        realm: &Realm,
        hashed_pin: &HashedPin,
    ) -> Result<TgkShare, RecoverError> {
        let blinded_pin = OprfClient::blind(hashed_pin.expose_secret(), &mut OsRng)
            .map_err(|_| RecoverError::Assertion)?;

        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request {
                blinded_pin: blinded_pin.message,
            }),
        );

        // This is a verbose way to copy some fields out to this outer scope.
        // It helps avoid having to process these fields at a high level of
        // indentation.
        struct OkResponse {
            blinded_oprf_pin: OprfBlindedResult,
            masked_tgk_share: MaskedTgkShare,
        }
        let OkResponse {
            blinded_oprf_pin,
            masked_tgk_share,
        } = match recover2_request.await {
            Err(RequestError::Transient) => return Err(RecoverError::Transient),
            Err(RequestError::Assertion) => return Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => return Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok {
                    blinded_oprf_pin,
                    masked_tgk_share,
                } => OkResponse {
                    blinded_oprf_pin,
                    masked_tgk_share,
                },

                Recover2Response::NotRegistered => {
                    return Err(RecoverError::NotRegistered);
                }

                Recover2Response::NoGuesses => {
                    return Err(RecoverError::InvalidPin {
                        guesses_remaining: 0,
                    });
                }
            },

            Ok(_) => return Err(RecoverError::Assertion),
        };

        let oprf_pin = blinded_pin
            .state
            .finalize(hashed_pin.expose_secret(), &blinded_oprf_pin)
            .map_err(|_| RecoverError::Assertion)?;

        let tgk_share = TgkShare::try_from_masked(&masked_tgk_share, &oprf_pin)
            .map_err(|_| RecoverError::Assertion)?;

        Ok(tgk_share)
    }

    /// Executes phase 3 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self))]
    async fn recover3(
        &self,
        realm: &Realm,
        tag: UnlockTag,
    ) -> Result<UserSecretShare, RecoverError> {
        let recover3_request =
            self.make_request(realm, SecretsRequest::Recover3(Recover3Request { tag }));

        match recover3_request.await {
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover3(rr)) => match rr {
                Recover3Response::Ok(secret_share) => Ok(secret_share),
                Recover3Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover3Response::BadUnlockTag { guesses_remaining } => {
                    Err(RecoverError::InvalidPin { guesses_remaining })
                }
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }
}
