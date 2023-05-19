use rand::rngs::OsRng;
use sharks::Sharks;
use std::iter::zip;
use tracing::instrument;

use loam_sdk_core::{
    requests::{
        Register1Response, Register2Request, Register2Response, SecretsRequest, SecretsResponse,
    },
    types::{MaskedTgkShare, OprfKey, OprfServer, Salt, UserSecretShare},
};

use crate::{
    http,
    request::{join_at_least_threshold, RequestError},
    types::{TagGeneratingKey, TgkShare},
    Client, Pin, Policy, Realm, Sleeper, UserSecret,
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

impl<S: Sleeper, Http: http::Client> Client<S, Http> {
    pub(crate) async fn perform_register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        let register1_requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.register1_on_realm(realm));
        join_at_least_threshold(register1_requests, self.configuration.register_threshold).await?;

        let salt = Salt::new_random(&mut OsRng);
        let (access_key, encryption_key) = pin
            .hash(self.configuration.pin_hashing_mode, &salt)
            .expect("pin hashing failed");

        let encrypted_user_secret = secret.encrypt(&encryption_key);

        let oprf_keys: Vec<OprfKey> = std::iter::repeat_with(|| OprfKey::new_random(&mut OsRng))
            .take(self.configuration.realms.len())
            .collect();

        let tgk = TagGeneratingKey::new_random();

        let tgk_shares: Vec<TgkShare> = Sharks(self.configuration.recover_threshold)
            .dealer_rng(tgk.expose_secret(), &mut OsRng)
            .take(self.configuration.realms.len())
            .map(TgkShare)
            .collect();

        let masked_tgk_shares: Vec<MaskedTgkShare> = zip(tgk_shares, &oprf_keys)
            .map(|(share, key)| {
                let oprf_server = OprfServer::new_with_key(key.expose_secret())
                    .expect("oprf key derivation failed");
                let oprf_result = oprf_server
                    .evaluate(access_key.expose_secret())
                    .expect("oprf pin evaluation failed")
                    .into();
                share.mask(&oprf_result)
            })
            .collect();

        let secret_shares: Vec<UserSecretShare> = Sharks(self.configuration.recover_threshold)
            .dealer_rng(encrypted_user_secret.expose_secret(), &mut OsRng)
            .take(self.configuration.realms.len())
            .map(|share| {
                UserSecretShare::try_from(Vec::<u8>::from(&share))
                    .expect("unexpected secret share length")
            })
            .collect();

        let register2_requests = zip4(
            &self.configuration.realms,
            oprf_keys,
            masked_tgk_shares,
            secret_shares,
        )
        .map(|(realm, oprf_key, masked_tgk_share, secret_share)| {
            self.register2_on_realm(
                realm,
                Register2Request {
                    salt: salt.to_owned(),
                    oprf_key,
                    tag: tgk.tag(&realm.id),
                    masked_tgk_share,
                    secret_share,
                    policy: policy.to_owned(),
                },
            )
        });

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
    zip(zip(a, b), zip(c, d)).map(|((a, b), (c, d))| (a, b, c, d))
}
