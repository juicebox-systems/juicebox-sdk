use rand::rngs::OsRng;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tracing::instrument;

use juicebox_sdk_core::{
    requests::{
        Recover1Response, Recover2Request, Recover2Response, Recover3Request, Recover3Response,
        SecretsRequest, SecretsResponse,
    },
    types::{
        EncryptedUserSecret, EncryptedUserSecretCommitment, OprfClient, OprfResult,
        RegistrationVersion, UnlockKey, UnlockKeyCommitment, UnlockKeyTag, UserSecretAccessKey,
        UserSecretEncryptionKeyScalarShare,
    },
};
use juicebox_sdk_secret_sharing::{
    recover_secret, recover_secret_combinatorially, Secret, SecretSharingError, Share,
};

use crate::{
    auth,
    configuration::CheckedConfiguration,
    http,
    request::{join_at_least_threshold, RequestError},
    types::{
        UnlockKeyScalar, UnlockKeyScalarShare, UserSecretEncryptionKey,
        UserSecretEncryptionKeyScalar,
    },
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

        let mut realms_per_version: HashMap<RegistrationVersion, Vec<Realm>> = HashMap::new();
        for (version, realm) in
            join_at_least_threshold(recover1_requests, configuration.recover_threshold).await?
        {
            realms_per_version.entry(version).or_default().push(realm);
        }

        realms_per_version
            .retain(|_, values| values.len() >= configuration.recover_threshold as usize);

        // We enforce a strict majority for the `recover_threshold`, so there should always
        // be one or none realms with consensus on a version available to recover from.
        assert!(realms_per_version.len() <= 1);

        let Some((version, realms)) = realms_per_version.into_iter().next() else {
            return Err(RecoverError::NotRegistered);
        };

        let (access_key, encryption_key_seed) = pin
            .hash(configuration.pin_hashing_mode, &version, info)
            .expect("pin hashing failed");

        let recover2_requests = realms
            .iter()
            .map(|realm| self.recover2_on_realm(realm, configuration, &version, &access_key));

        let mut unlock_key_scalar_shares_by_commitment: HashMap<UnlockKeyCommitment, Vec<Share>> =
            HashMap::new();

        for (share, commitment) in
            join_at_least_threshold(recover2_requests, configuration.recover_threshold).await?
        {
            unlock_key_scalar_shares_by_commitment
                .entry(commitment)
                .or_default()
                .push(share);
        }

        unlock_key_scalar_shares_by_commitment
            .retain(|_, values| values.len() >= configuration.recover_threshold as usize);

        // We enforce a strict majority for the `recover_threshold`, so there should always
        // be one or none realms with consensus on an unlock key commitment to recover from.
        assert!(unlock_key_scalar_shares_by_commitment.len() <= 1);

        let Some((unlock_key_commitment, unlock_key_scalar_shares)) = unlock_key_scalar_shares_by_commitment.into_iter().next() else {
            return Err(RecoverError::Assertion);
        };

        let unlock_key = match recover_secret_combinatorially(
            &unlock_key_scalar_shares,
            configuration.recover_threshold,
            |secret| {
                let our_commitment = UnlockKeyCommitment::derive(
                    &UnlockKeyScalar::new(secret.to_owned()).as_hash(),
                    &access_key,
                );
                bool::from(unlock_key_commitment.ct_eq(&our_commitment))
            },
        ) {
            Ok(secret) => UnlockKey::derive(&UnlockKeyScalar::new(secret).as_hash()),
            Err(SecretSharingError::NoValidCombinations) => {
                // We couldn't validate the unlock key commitment with any
                // share combination so we either have the wrong PIN or the
                // realms are misbehaving. Use a null unlock key to proceed
                // to register3 and notify the realms we weren't able to
                // recover it.
                UnlockKey::from([0; 32])
            }
            Err(_) => {
                return Err(RecoverError::Assertion);
            }
        };

        let recover3_requests = realms.iter().map(|realm| {
            self.recover3_on_realm(
                realm,
                configuration,
                &version,
                UnlockKeyTag::derive(&unlock_key, &realm.id),
            )
        });

        let mut encryption_key_scalar_shares_by_encrypted_secret: HashMap<
            EncryptedUserSecret,
            Vec<Share>,
        > = HashMap::new();

        for (share, encrypted_secret, commitment, realm) in
            join_at_least_threshold(recover3_requests, configuration.recover_threshold).await?
        {
            let our_commitment = EncryptedUserSecretCommitment::derive(
                &unlock_key,
                &realm.id,
                &UserSecretEncryptionKeyScalarShare::from(*share.secret.expose_secret()),
                &encrypted_secret,
            );

            // We can't use the share from this realm, but we continue
            // as there may still be enough material from other realms.
            if !bool::from(our_commitment.ct_eq(&commitment)) {
                continue;
            }

            encryption_key_scalar_shares_by_encrypted_secret
                .entry(encrypted_secret)
                .or_default()
                .push(share);
        }

        encryption_key_scalar_shares_by_encrypted_secret
            .retain(|_, values| values.len() >= configuration.recover_threshold as usize);

        // We enforce a strict majority for the `recover_threshold`, so there should always
        // be one or none realms with consensus on an encrypted secret to recover from.
        assert!(encryption_key_scalar_shares_by_encrypted_secret.len() <= 1);

        let Some((encrypted_secret, encryption_key_scalar_shares)) = encryption_key_scalar_shares_by_encrypted_secret.into_iter().next() else {
            return Err(RecoverError::Assertion);
        };

        match recover_secret(&encryption_key_scalar_shares) {
            Ok(secret) => {
                let scalar = UserSecretEncryptionKeyScalar::new(secret);
                let encryption_key = UserSecretEncryptionKey::derive(&encryption_key_seed, &scalar);

                Ok(UserSecret::decrypt(&encrypted_secret, &encryption_key))
            }
            Err(_) => Err(RecoverError::Assertion),
        }
    }

    /// Performs phase 1 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover1_on_realm(
        &self,
        realm: &Realm,
    ) -> Result<(RegistrationVersion, Realm), RecoverError> {
        match self.make_request(realm, SecretsRequest::Recover1).await {
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Ok(SecretsResponse::Recover1(response)) => match response {
                Recover1Response::Ok { version } => Ok((version, realm.to_owned())),
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
    ) -> Result<(Share, UnlockKeyCommitment), RecoverError> {
        let oprf_blinded_input = OprfClient::blind(access_key.expose_secret(), &mut OsRng)
            .expect("failed to blind access_key");

        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request {
                version: version.to_owned(),
                oprf_blinded_input: oprf_blinded_input.message.into(),
            }),
        );

        let (oprf_blinded_result, masked_unlock_key_share, unlock_key_commitment) =
            match recover2_request.await {
                Err(RequestError::Transient) => return Err(RecoverError::Transient),
                Err(RequestError::Assertion) => return Err(RecoverError::Assertion),
                Err(RequestError::InvalidAuth) => return Err(RecoverError::InvalidAuth),

                Ok(SecretsResponse::Recover2(rr)) => match rr {
                    Recover2Response::Ok {
                        oprf_blinded_result,
                        masked_unlock_key_scalar_share,
                        unlock_key_commitment,
                    } => (
                        oprf_blinded_result,
                        masked_unlock_key_scalar_share,
                        unlock_key_commitment,
                    ),

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

        let oprf_result: OprfResult = oprf_blinded_input
            .state
            .finalize(
                access_key.expose_secret(),
                &oprf_blinded_result.expose_secret(),
            )
            .expect("failed to unblind blinded_oprf_input")
            .into();

        let unlock_key_scalar_share = Share {
            index: configuration
                .share_index(&realm.id)
                .ok_or(RecoverError::Assertion)?,
            secret: Secret::from(
                *UnlockKeyScalarShare::unmask(&masked_unlock_key_share, &oprf_result)
                    .expose_secret(),
            ),
        };

        Ok((unlock_key_scalar_share, unlock_key_commitment))
    }

    /// Performs phase 3 of recovery on a particular realm.
    #[instrument(level = "trace", skip(self))]
    async fn recover3_on_realm(
        &self,
        realm: &Realm,
        configuration: &CheckedConfiguration,
        version: &RegistrationVersion,
        unlock_key_tag: UnlockKeyTag,
    ) -> Result<
        (
            Share,
            EncryptedUserSecret,
            EncryptedUserSecretCommitment,
            Realm,
        ),
        RecoverError,
    > {
        let recover3_request = self.make_request(
            realm,
            SecretsRequest::Recover3(Recover3Request {
                version: version.to_owned(),
                unlock_key_tag,
            }),
        );

        match recover3_request.await {
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover3(rr)) => match rr {
                Recover3Response::Ok {
                    user_secret_encryption_key_scalar_share,
                    encrypted_user_secret,
                    encrypted_user_secret_commitment,
                } => {
                    let secret_share = Share {
                        index: configuration
                            .share_index(&realm.id)
                            .ok_or(RecoverError::Assertion)?,
                        secret: Secret::from(
                            *user_secret_encryption_key_scalar_share.expose_secret(),
                        ),
                    };
                    Ok((
                        secret_share,
                        encrypted_user_secret,
                        encrypted_user_secret_commitment,
                        realm.to_owned(),
                    ))
                }
                Recover3Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover3Response::NoGuesses => Err(RecoverError::InvalidPin {
                    guesses_remaining: 0,
                }),
                Recover3Response::BadUnlockKeyTag { guesses_remaining } => {
                    Err(RecoverError::InvalidPin { guesses_remaining })
                }
                Recover3Response::VersionMismatch => Err(RecoverError::Assertion),
            },
            Ok(_) => Err(RecoverError::Assertion),
        }
    }
}
