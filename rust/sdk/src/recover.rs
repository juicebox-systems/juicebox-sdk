use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};
use subtle::ConstantTimeEq;
use tracing::instrument;

use juicebox_oprf as oprf;
use juicebox_realm_api::{
    requests::{
        Recover1Response, Recover2Request, Recover2Response, Recover3Request, Recover3Response,
        SecretsRequest, SecretsResponse,
    },
    signing::OprfVerifyingKey,
    types::{
        EncryptedUserSecret, EncryptedUserSecretCommitment, RegistrationVersion,
        UnlockKeyCommitment, UnlockKeyTag, UserSecretEncryptionKeyScalarShare,
    },
};
use juicebox_secret_sharing::{recover_secret, RecoverSecretError, Share};

use crate::{
    auth,
    configuration::CheckedConfiguration,
    http,
    request::{join_at_least_threshold, RequestError},
    types::{
        derive_unlock_key_and_commitment, UserSecretEncryptionKey, UserSecretEncryptionKeyScalar,
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

    /// The SDK software is too old to communicate with this realm
    /// and must be upgraded.
    UpgradeRequired,

    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion,

    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient,
}

impl Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for RecoverError {}

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
    #[instrument(level = "trace", skip_all, err(level = "trace", Debug))]
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

        let (oprf_blinding_factor, oprf_blinded_input) =
            oprf::start(access_key.expose_secret(), &mut OsRng);

        let recover2_requests = realms.iter().map(|realm| {
            self.recover2_on_realm(realm, configuration, &version, &oprf_blinded_input)
        });

        let mut oprf_blinded_result_shares_by_commitment_and_verifying_key: HashMap<_, Vec<_>> =
            HashMap::new();

        // TODO: this should stop after finding threshold realms that agree on
        // commitment and verifying key
        for (oprf_verifying_key, share, commitment, guesses_remaining) in
            join_at_least_threshold(recover2_requests, configuration.recover_threshold).await?
        {
            oprf_blinded_result_shares_by_commitment_and_verifying_key
                .entry((commitment, oprf_verifying_key))
                .or_default()
                .push((share, guesses_remaining));
        }

        oprf_blinded_result_shares_by_commitment_and_verifying_key
            .retain(|_, values| values.len() >= configuration.recover_threshold as usize);

        // We enforce a strict majority for the `recover_threshold`, so there should always
        // be one or none realms with consensus on an unlock key commitment and verifying
        // key to recover from.
        assert!(oprf_blinded_result_shares_by_commitment_and_verifying_key.len() <= 1);

        let Some(((unlock_key_commitment, _), oprf_blinded_result_shares_and_guesses_remaining)) =
            oprf_blinded_result_shares_by_commitment_and_verifying_key
                .into_iter()
                .next()
        else {
            return Err(RecoverError::Assertion);
        };

        let (oprf_blinded_result_shares, all_guesses_remaining): (
            Vec<Share<RistrettoPoint>>,
            Vec<u16>,
        ) = oprf_blinded_result_shares_and_guesses_remaining
            .into_iter()
            .unzip();

        let oprf_blinded_result = match recover_secret(&oprf_blinded_result_shares) {
            Ok(blinded_result) => oprf::BlindedOutput::from(blinded_result),
            Err(RecoverSecretError::DuplicateShares) => return Err(RecoverError::Assertion),
        };
        let oprf_result = oprf::finalize(
            access_key.expose_secret(),
            &oprf_blinding_factor,
            &oprf_blinded_result,
        );

        let (unlock_key, our_commitment) = derive_unlock_key_and_commitment(&oprf_result);
        if !bool::from(unlock_key_commitment.ct_eq(&our_commitment)) {
            let guesses_remaining = all_guesses_remaining.into_iter().min().unwrap();
            return Err(RecoverError::InvalidPin { guesses_remaining });
        }

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
            Vec<Share<Scalar>>,
        > = HashMap::new();

        for (share, encrypted_secret, commitment, realm) in
            join_at_least_threshold(recover3_requests, configuration.recover_threshold).await?
        {
            let our_commitment = EncryptedUserSecretCommitment::derive(
                &unlock_key,
                &realm.id,
                &UserSecretEncryptionKeyScalarShare::from(share.secret),
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

        let Some((encrypted_secret, encryption_key_scalar_shares)) =
            encryption_key_scalar_shares_by_encrypted_secret
                .into_iter()
                .next()
        else {
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
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn recover1_on_realm(
        &self,
        realm: &Realm,
    ) -> Result<(RegistrationVersion, Realm), RecoverError> {
        match self.make_request(realm, SecretsRequest::Recover1).await {
            Err(RequestError::UpgradeRequired) => Err(RecoverError::UpgradeRequired),
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
    #[instrument(level = "trace", skip_all, err(level = "trace", Debug))]
    async fn recover2_on_realm(
        &self,
        realm: &Realm,
        configuration: &CheckedConfiguration,
        version: &RegistrationVersion,
        oprf_blinded_input: &oprf::BlindedInput,
    ) -> Result<
        (
            OprfVerifyingKey,
            Share<RistrettoPoint>,
            UnlockKeyCommitment,
            u16,
        ),
        RecoverError,
    > {
        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request {
                version: version.to_owned(),
                oprf_blinded_input: oprf_blinded_input.to_owned(),
            }),
        );

        let (
            oprf_signed_public_key,
            oprf_blinded_result,
            oprf_proof,
            unlock_key_commitment,
            guesses_remaining,
        ) = match recover2_request.await {
            Err(RequestError::UpgradeRequired) => return Err(RecoverError::UpgradeRequired),
            Err(RequestError::Transient) => return Err(RecoverError::Transient),
            Err(RequestError::Assertion) => return Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => return Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok {
                    oprf_signed_public_key,
                    oprf_blinded_result,
                    oprf_proof,
                    unlock_key_commitment,
                    num_guesses,
                    guess_count,
                } => (
                    oprf_signed_public_key,
                    oprf_blinded_result,
                    oprf_proof,
                    unlock_key_commitment,
                    num_guesses - guess_count,
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

        oprf_signed_public_key
            .verify(&realm.id)
            .map_err(|_| RecoverError::Assertion)?;

        oprf::verify_proof(
            oprf_blinded_input,
            &oprf_blinded_result,
            &oprf_signed_public_key.public_key,
            &oprf_proof,
        )
        .map_err(|_| RecoverError::Assertion)?;

        let oprf_blinded_result_share = Share {
            index: configuration
                .share_index(&realm.id)
                .ok_or(RecoverError::Assertion)?,
            secret: oprf_blinded_result.to_point(),
        };

        Ok((
            oprf_signed_public_key.verifying_key,
            oprf_blinded_result_share,
            unlock_key_commitment,
            guesses_remaining,
        ))
    }

    /// Performs phase 3 of recovery on a particular realm.
    #[instrument(level = "trace", skip_all)]
    async fn recover3_on_realm(
        &self,
        realm: &Realm,
        configuration: &CheckedConfiguration,
        version: &RegistrationVersion,
        unlock_key_tag: UnlockKeyTag,
    ) -> Result<
        (
            Share<Scalar>,
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
            Err(RequestError::UpgradeRequired) => Err(RecoverError::UpgradeRequired),
            Err(RequestError::Transient) => Err(RecoverError::Transient),
            Err(RequestError::Assertion) => Err(RecoverError::Assertion),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover3(rr)) => match rr {
                Recover3Response::Ok {
                    encryption_key_scalar_share,
                    encrypted_secret,
                    encrypted_secret_commitment,
                } => {
                    let secret_share = Share {
                        index: configuration
                            .share_index(&realm.id)
                            .ok_or(RecoverError::Assertion)?,
                        secret: encryption_key_scalar_share.to_scalar(),
                    };
                    Ok((
                        secret_share,
                        encrypted_secret,
                        encrypted_secret_commitment,
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
