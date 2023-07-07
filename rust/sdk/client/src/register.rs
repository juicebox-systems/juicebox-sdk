use rand::rngs::OsRng;
use tracing::instrument;

use juicebox_sdk_core::{
    requests::{
        Register1Response, Register2Request, Register2Response, SecretsRequest, SecretsResponse,
    },
    types::{
        EncryptedUserSecretCommitment, MaskedUnlockKeyScalarShare, OprfRootSeed, OprfSeed,
        OprfServer, RegistrationVersion, UnlockKey, UnlockKeyCommitment, UnlockKeyScalar,
        UnlockKeyTag, UserSecretEncryptionKeyScalarShare, OPRF_KEY_INFO,
    },
};

use crate::{
    auth, http,
    request::{join_at_least_threshold, RequestError},
    secret_sharing,
    types::{UnlockKeyScalarShare, UserSecretEncryptionKey, UserSecretEncryptionKeyScalar},
    Client, Pin, Policy, Realm, Sleeper, UserInfo, UserSecret,
};

/// Error return type for [`Client::register`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum RegisterError {
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
    pub(crate) async fn perform_register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        info: &UserInfo,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        let register1_requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.register1_on_realm(realm));
        join_at_least_threshold(register1_requests, self.configuration.register_threshold).await?;

        let version = RegistrationVersion::new_random(&mut OsRng);

        let (access_key, encryption_key_seed) = pin
            .hash(self.configuration.pin_hashing_mode, &version, info)
            .expect("pin hashing failed");

        let encryption_key_scalar = UserSecretEncryptionKeyScalar::new_random();
        let encryption_key_scalar_shares: Vec<UserSecretEncryptionKeyScalarShare> =
            secret_sharing::create(
                &encryption_key_scalar.0,
                self.configuration.recover_threshold,
                self.configuration.share_count(),
            )
            .map(|share| UserSecretEncryptionKeyScalarShare::from(*share.value.expose_secret()))
            .collect();

        let encryption_key =
            UserSecretEncryptionKey::derive(&encryption_key_seed, &encryption_key_scalar);
        let encrypted_secret = secret.encrypt(&encryption_key);

        let unlock_key_scalar = UnlockKeyScalar::new_random(&mut OsRng);
        let unlock_key_scalar_hash = unlock_key_scalar.as_hash();

        let oprf_root_seed = OprfRootSeed::derive(&unlock_key_scalar_hash, &access_key);

        let oprf_seeds: Vec<OprfSeed> = self
            .configuration
            .realms
            .iter()
            .map(|realm| OprfSeed::derive(&oprf_root_seed, &realm.id))
            .collect();

        let masked_unlock_key_scalar_shares: Vec<MaskedUnlockKeyScalarShare> =
            secret_sharing::create(
                &unlock_key_scalar.0,
                self.configuration.recover_threshold,
                self.configuration.share_count(),
            )
            .zip(&oprf_seeds)
            .map(|(share, oprf_seed)| {
                let oprf_server =
                    OprfServer::new_from_seed(oprf_seed.expose_secret(), OPRF_KEY_INFO)
                        .expect("oprf key derivation failed");
                let oprf_result = oprf_server
                    .evaluate(access_key.expose_secret())
                    .expect("oprf pin evaluation failed")
                    .into();

                let unmasked_share = UnlockKeyScalarShare::from(*share.value.expose_secret());
                unmasked_share.mask(&oprf_result)
            })
            .collect();

        let unlock_key = UnlockKey::derive(&unlock_key_scalar_hash);
        let unlock_key_commitment =
            UnlockKeyCommitment::derive(&unlock_key_scalar_hash, &access_key);

        let register2_requests = zip4(
            &self.configuration.realms,
            oprf_seeds,
            encryption_key_scalar_shares,
            masked_unlock_key_scalar_shares,
        )
        .map(
            |(realm, oprf_seed, encryption_key_scalar_share, masked_unlock_key_scalar_share)| {
                self.register2_on_realm(
                    realm,
                    Register2Request {
                        version: version.to_owned(),
                        oprf_seed,
                        unlock_key_tag: UnlockKeyTag::derive(&unlock_key, &realm.id),
                        unlock_key_commitment: unlock_key_commitment.to_owned(),
                        masked_unlock_key_scalar_share,
                        user_secret_encryption_key_scalar_share: encryption_key_scalar_share
                            .to_owned(),
                        encrypted_user_secret: encrypted_secret.to_owned(),
                        encrypted_user_secret_commitment: EncryptedUserSecretCommitment::derive(
                            &unlock_key,
                            &realm.id,
                            &encryption_key_scalar_share,
                            &encrypted_secret,
                        ),
                        policy: policy.to_owned(),
                    },
                )
            },
        );

        join_at_least_threshold(register2_requests, self.configuration.register_threshold).await?;

        Ok(())
    }

    /// Executes phase 1 of registration on a particular realm.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn register1_on_realm(&self, realm: &Realm) -> Result<(), RegisterError> {
        match self.make_request(realm, SecretsRequest::Register1).await {
            Err(RequestError::InvalidAuth) => Err(RegisterError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RegisterError::Assertion),
            Err(RequestError::Transient) => Err(RegisterError::Transient),
            Ok(SecretsResponse::Register1(Register1Response::Ok)) => Ok(()),
            Ok(_) => Err(RegisterError::Assertion),
        }
    }

    /// Executes phase 2 of registration on a particular realm.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn register2_on_realm(
        &self,
        realm: &Realm,
        request: Register2Request,
    ) -> Result<(), RegisterError> {
        match self
            .make_request(realm, SecretsRequest::Register2(Box::new(request)))
            .await
        {
            Err(RequestError::InvalidAuth) => Err(RegisterError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RegisterError::Assertion),
            Err(RequestError::Transient) => Err(RegisterError::Transient),
            Ok(SecretsResponse::Register2(Register2Response::Ok)) => Ok(()),
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
    let iter = a.into_iter().zip(b).zip(c).zip(d);
    iter.map(|(((a, b), c), d)| (a, b, c, d))
}

mod tests {
    #[test]
    fn test_zip4() {
        let a = vec![1, 2, 3];
        let b = vec!['a', 'b', 'c'];
        let c = vec![true, false, true];
        let d = vec!["x", "y", "z"];

        let zipped: Vec<_> = super::zip4(a, b, c, d).collect();

        let expected = vec![
            (1, 'a', true, "x"),
            (2, 'b', false, "y"),
            (3, 'c', true, "z"),
        ];

        assert_eq!(zipped, expected);
    }
}
