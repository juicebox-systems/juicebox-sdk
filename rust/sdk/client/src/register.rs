use futures::future::join_all;
use loam_sdk_core::{requests::Register1Response, types::MaskedTgkShare};
use rand::rngs::OsRng;
use sharks::Sharks;
use std::iter::zip;
use tracing::instrument;

use loam_sdk_core::{
    requests::{Register2Request, Register2Response, SecretsRequest, SecretsResponse},
    types::{OprfKey, OprfResult, OprfServer, Salt, UserSecretShare},
};

use crate::{
    http,
    request::RequestError,
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
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
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

        let mut register1_errors: Vec<RegisterError> = Vec::new();
        for result in join_all(register1_requests).await {
            match result {
                Ok(()) => {}
                Err(error) => self.collect_errors(
                    &mut register1_errors,
                    error,
                    self.configuration.realms.len(),
                    self.configuration.register_threshold.into(),
                )?,
            }
        }

        let salt = Salt::new_random(&mut OsRng);
        let hashed_pin = pin
            .hash(&self.configuration.pin_hashing_mode, &salt)
            .ok_or(RegisterError::Assertion)?;

        let oprf_keys: Vec<OprfKey> = std::iter::repeat(())
            .take(self.configuration.realms.len())
            .map(|_| OprfKey::new_random(&mut OsRng).ok_or(RegisterError::Assertion))
            .collect::<Result<Vec<_>, _>>()?;

        let tgk = TagGeneratingKey::new_random();

        let masked_tgk_shares: Vec<MaskedTgkShare> = Sharks(self.configuration.recover_threshold)
            .dealer_rng(tgk.expose_secret(), &mut OsRng)
            .take(self.configuration.realms.len())
            .map(TgkShare)
            .enumerate()
            .map(|(index, share)| {
                let oprf_key = oprf_keys.get(index).ok_or(RegisterError::Assertion)?;
                let oprf_server = OprfServer::new_with_key(oprf_key.expose_secret())
                    .map_err(|_| RegisterError::Assertion)?;
                let oprf_pin = oprf_server
                    .evaluate(hashed_pin.expose_secret())
                    .map_err(|_| RegisterError::Assertion)?;
                Ok(share.mask(&OprfResult(oprf_pin)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let secret_shares: Vec<UserSecretShare> = Sharks(self.configuration.recover_threshold)
            .dealer_rng(secret.expose_secret(), &mut OsRng)
            .take(self.configuration.realms.len())
            .map(|share| UserSecretShare::from(Vec::<u8>::from(&share)))
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
                    tag: tgk.tag(&realm.public_key),
                    masked_tgk_share,
                    secret_share,
                    policy: policy.to_owned(),
                },
            )
        });

        let mut register2_errors = Vec::new();
        for result in join_all(register2_requests).await {
            if let Err(error) = result {
                self.collect_errors(
                    &mut register2_errors,
                    error,
                    self.configuration.realms.len(),
                    self.configuration.register_threshold.into(),
                )?;
            }
        }
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
            .make_request(realm, SecretsRequest::Register2(request))
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
