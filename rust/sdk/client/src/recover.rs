use rand::rngs::OsRng;
use std::collections::HashMap;
use tracing::instrument;

use juicebox_sdk_core::{
    requests::{
        Recover1Response, Recover2Request, Recover2Response, Recover3Request, Recover3Response,
        SecretsRequest, SecretsResponse,
    },
    types::{OprfClient, OprfResult, RegistrationVersion, Salt, SaltShare, UnlockTag},
};

use crate::{
    auth,
    configuration::CheckedConfiguration,
    http,
    request::{join_at_least_threshold, join_until_threshold, RequestError},
    secret_sharing,
    types::{EncryptedUserSecret, UnlockKey, UnlockKeyShare, UserSecretAccessKey},
    Client, Pin, Realm, Sleeper, UserInfo, UserSecret,
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

impl<S: Sleeper, Http: http::Client, Atm: auth::AuthTokenManager> Client<S, Http, Atm> {
    pub(crate) async fn perform_recover(
        &self,
        pin: &Pin,
        info: &UserInfo,
    ) -> Result<UserSecret, RecoverError> {
        let mut configuration = &self.configuration;
        let mut iter = self.previous_configurations.iter();
        loop {
            return match self
                .perform_recover_with_configuration(pin, info, configuration)
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
        info: &UserInfo,
        configuration: &CheckedConfiguration,
    ) -> Result<UserSecret, RecoverError> {
        let recover1_requests = configuration
            .realms
            .iter()
            .map(|realm| self.recover1_on_realm(realm));

        let mut salt_share_and_realm_per_version: HashMap<
            RegistrationVersion,
            Vec<(SaltShare, Realm)>,
        > = HashMap::new();
        for (version, salt_share, realm) in
            join_at_least_threshold(recover1_requests, configuration.recover_threshold).await?
        {
            salt_share_and_realm_per_version
                .entry(version)
                .or_default()
                .push((salt_share, realm));
        }

        salt_share_and_realm_per_version
            .retain(|_, values| values.len() >= configuration.recover_threshold.into());

        // We enforce a strict majority for the `recover_threshold`, so there should always
        // be one or none realms with consensus on a version available to recover from.
        assert!(salt_share_and_realm_per_version.len() <= 1);

        let Some((version, salt_shares_and_realms)) = salt_share_and_realm_per_version.into_iter().next() else {
            return Err(RecoverError::NotRegistered);
        };

        let salt_shares: Vec<secret_sharing::Share> = salt_shares_and_realms
            .iter()
            .map(|(share, realm)| {
                let position = configuration
                    .share_position(&realm.id)
                    .ok_or(RecoverError::Assertion)?;
                let bytes = secret_sharing::ShareBytes::from(share.expose_secret());
                secret_sharing::Share::try_from(&position, &bytes)
                    .map_err(|_| RecoverError::Assertion)
            })
            .collect::<Result<_, _>>()?;

        let salt: Salt = match secret_sharing::reconstruct(
            salt_shares.iter(),
            configuration.recover_threshold,
        ) {
            Ok(salt) => Salt::try_from(salt).map_err(|_| RecoverError::Assertion)?,
            Err(_) => {
                return Err(RecoverError::Assertion);
            }
        };

        let (_, realms): (Vec<SaltShare>, Vec<Realm>) = salt_shares_and_realms.into_iter().unzip();

        let (access_key, encryption_key) = pin
            .hash(configuration.pin_hashing_mode, &salt, info)
            .expect("pin hashing failed");

        let recover2_requests = realms
            .iter()
            .map(|realm| self.recover2_on_realm(realm, configuration, &version, &access_key));

        let unlock_key_shares: Vec<secret_sharing::Share> =
            join_until_threshold(recover2_requests, configuration.recover_threshold).await?;

        let unlock_key = match secret_sharing::reconstruct(
            unlock_key_shares.iter(),
            configuration.recover_threshold,
        ) {
            Ok(unlock_key) => {
                UnlockKey::try_from(unlock_key).map_err(|_| RecoverError::Assertion)?
            }
            Err(_) => {
                return Err(RecoverError::Assertion);
            }
        };

        let recover3_requests = realms.iter().map(|realm| {
            self.recover3_on_realm(realm, configuration, &version, unlock_key.tag(&realm.id))
        });

        let secret_shares: Vec<secret_sharing::Share> =
            join_at_least_threshold(recover3_requests, configuration.recover_threshold).await?;

        match secret_sharing::reconstruct(secret_shares.iter(), configuration.recover_threshold) {
            Ok(secret) => Ok(EncryptedUserSecret::try_from(secret)
                .map_err(|_| RecoverError::Assertion)?
                .decrypt(&encryption_key)),
            Err(_) => Err(RecoverError::Assertion),
        }
    }

    /// Performs phase 1 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover1_on_realm(
        &self,
        realm: &Realm,
    ) -> Result<(RegistrationVersion, SaltShare, Realm), RecoverError> {
        match self.make_request(realm, SecretsRequest::Recover1).await {
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Ok(SecretsResponse::Recover1(response)) => match response {
                Recover1Response::Ok {
                    version,
                    salt_share,
                } => Ok((version, salt_share, realm.to_owned())),
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
        configuration: &CheckedConfiguration,
        version: &RegistrationVersion,
        access_key: &UserSecretAccessKey,
    ) -> Result<secret_sharing::Share, RecoverError> {
        let blinded_oprf_input = OprfClient::blind(access_key.expose_secret(), &mut OsRng)
            .expect("failed to blind access_key");

        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request {
                version: version.to_owned(),
                blinded_oprf_input: blinded_oprf_input.message.into(),
            }),
        );

        let (blinded_oprf_result, masked_unlock_key_share) = match recover2_request.await {
            Err(RequestError::Transient) => return Err(RecoverError::Transient),
            Err(RequestError::Assertion) => return Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => return Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok {
                    blinded_oprf_result,
                    masked_unlock_key_share,
                } => (blinded_oprf_result, masked_unlock_key_share),

                Recover2Response::VersionMismatch => {
                    return Err(RecoverError::Assertion);
                }

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

        let share_bytes = secret_sharing::ShareBytes::from(
            UnlockKeyShare::try_from_masked(&masked_unlock_key_share, &oprf_result)
                .expect("failed to unmask unlock_key_share")
                .expose_secret(),
        );

        let share_position = configuration
            .share_position(&realm.id)
            .ok_or(RecoverError::Assertion)?;
        let unlock_key_share = secret_sharing::Share::try_from(&share_position, &share_bytes)
            .map_err(|_| RecoverError::Assertion)?;

        Ok(unlock_key_share)
    }

    /// Performs phase 3 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self))]
    async fn recover3_on_realm(
        &self,
        realm: &Realm,
        configuration: &CheckedConfiguration,
        version: &RegistrationVersion,
        tag: UnlockTag,
    ) -> Result<secret_sharing::Share, RecoverError> {
        let recover3_request = self.make_request(
            realm,
            SecretsRequest::Recover3(Recover3Request {
                version: version.to_owned(),
                tag,
            }),
        );

        match recover3_request.await {
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover3(rr)) => match rr {
                Recover3Response::Ok { secret_share } => {
                    let share_bytes =
                        secret_sharing::ShareBytes::from(secret_share.expose_secret());
                    let share_position = configuration
                        .share_position(&realm.id)
                        .ok_or(RecoverError::Assertion)?;
                    let secret_share =
                        secret_sharing::Share::try_from(&share_position, &share_bytes)
                            .map_err(|_| RecoverError::Assertion)?;
                    Ok(secret_share)
                }
                Recover3Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover3Response::NoGuesses => Err(RecoverError::InvalidPin {
                    guesses_remaining: 0,
                }),
                Recover3Response::BadUnlockTag { guesses_remaining } => {
                    Err(RecoverError::InvalidPin { guesses_remaining })
                }
                Recover3Response::VersionMismatch => Err(RecoverError::Assertion),
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }
}
