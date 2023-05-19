use rand::rngs::OsRng;
use sharks::Sharks;
use std::collections::HashMap;
use tracing::instrument;

use loam_sdk_core::{
    requests::{
        Recover1Response, Recover2Request, Recover2Response, Recover3Request, Recover3Response,
        SecretsRequest, SecretsResponse,
    },
    types::{OprfClient, OprfResult, Salt, UnlockTag, UserSecretShare},
};

use crate::{
    http,
    request::{join_at_least_threshold, join_until_threshold, RequestError},
    types::{
        CheckedConfiguration, EncryptedUserSecret, TagGeneratingKey, TgkShare, UserSecretAccessKey,
    },
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

    /// Performs phase 1 of recovery for the parameters specified in a given
    /// configuration. If successful, attempts to complete recovery for each
    /// subset of realms larger than the recover threshold with matching salts.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn perform_recover_with_configuration(
        &self,
        pin: &Pin,
        configuration: &CheckedConfiguration,
    ) -> Result<UserSecret, RecoverError> {
        let recover1_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover1_on_realm(realm));

        let mut realms_per_salt: HashMap<Salt, Vec<Realm>> = HashMap::new();
        for (salt, realm) in
            join_at_least_threshold(recover1_requests, configuration.recover_threshold).await?
        {
            realms_per_salt.entry(salt).or_default().push(realm);
        }

        realms_per_salt.retain(|_, realms| realms.len() >= configuration.recover_threshold.into());

        // We enforce a strict majority for the `recover_threshold`, so there should always
        // be one or none realms with consensus on a salt available to recover from.
        assert!(realms_per_salt.len() <= 1);

        let Some((salt, realms)) = realms_per_salt.iter().next() else {
            return Err(RecoverError::NotRegistered);
        };

        let (access_key, encryption_key) = pin
            .hash(configuration.pin_hashing_mode, salt)
            .expect("pin hashing failed");

        let recover2_requests = realms
            .iter()
            .map(|realm| self.recover2_on_realm(realm, &access_key));

        let tgk_shares: Vec<TgkShare> =
            join_until_threshold(recover2_requests, configuration.recover_threshold).await?;

        let tgk = match Sharks(configuration.recover_threshold)
            .recover(tgk_shares.iter().map(|share| &share.0))
        {
            Ok(tgk) => TagGeneratingKey::try_from(tgk).map_err(|_| RecoverError::Assertion)?,
            Err(_) => {
                return Err(RecoverError::Assertion);
            }
        };

        let recover3_requests = realms.iter().map(|realm| async {
            let share: UserSecretShare = self.recover3_on_realm(realm, tgk.tag(&realm.id)).await?;
            sharks::Share::try_from(share.expose_secret()).map_err(|_| RecoverError::Assertion)
        });

        let secret_shares: Vec<sharks::Share> =
            join_at_least_threshold(recover3_requests, configuration.recover_threshold).await?;

        match Sharks(configuration.recover_threshold).recover(&secret_shares) {
            Ok(secret) => Ok(EncryptedUserSecret::try_from(secret)
                .map_err(|_| RecoverError::Assertion)?
                .decrypt(&encryption_key)),
            Err(_) => Err(RecoverError::Assertion),
        }
    }

    /// Performs phase 1 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover1_on_realm(&self, realm: &Realm) -> Result<(Salt, Realm), RecoverError> {
        match self.make_request(realm, SecretsRequest::Recover1).await {
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Ok(SecretsResponse::Recover1(response)) => match response {
                Recover1Response::Ok { salt } => Ok((salt, realm.to_owned())),
                Recover1Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover1Response::NoGuesses => Err(RecoverError::InvalidPin {
                    guesses_remaining: 0,
                }),
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }

    /// Performs phase 2 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover2_on_realm(
        &self,
        realm: &Realm,
        access_key: &UserSecretAccessKey,
    ) -> Result<TgkShare, RecoverError> {
        let blinded_oprf_input = OprfClient::blind(access_key.expose_secret(), &mut OsRng)
            .expect("failed to blind access_key");

        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request {
                blinded_oprf_input: blinded_oprf_input.message.into(),
            }),
        );

        let (blinded_oprf_result, masked_tgk_share) = match recover2_request.await {
            Err(RequestError::Transient) => return Err(RecoverError::Transient),
            Err(RequestError::Assertion) => return Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => return Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok {
                    blinded_oprf_result,
                    masked_tgk_share,
                } => (blinded_oprf_result, masked_tgk_share),

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

        let oprf_result: OprfResult = blinded_oprf_input
            .state
            .finalize(
                access_key.expose_secret(),
                &blinded_oprf_result.expose_secret(),
            )
            .expect("failed to unblind blinded_oprf_input")
            .into();

        let tgk_share = TgkShare::try_from_masked(&masked_tgk_share, &oprf_result)
            .expect("failed to unmask tgk_share");

        Ok(tgk_share)
    }

    /// Performs phase 3 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self))]
    async fn recover3_on_realm(
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
                Recover3Response::Ok { secret_share } => Ok(secret_share),
                Recover3Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover3Response::NoGuesses => Err(RecoverError::InvalidPin {
                    guesses_remaining: 0,
                }),
                Recover3Response::BadUnlockTag { guesses_remaining } => {
                    Err(RecoverError::InvalidPin { guesses_remaining })
                }
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }
}
