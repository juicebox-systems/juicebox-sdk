use futures::future::join_all;
use loam_sdk_core::types::MaskedTgkShare;
use rand::rngs::OsRng;
use sharks::Sharks;
use std::collections::BTreeSet;
use std::iter::zip;
use tracing::instrument;

use loam_sdk_core::{
    requests::{Register2Request, Register2Response, SecretsRequest, SecretsResponse},
    types::{GenerationNumber, OprfKey, OprfResult, OprfServer, Salt, UserSecretShare},
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
    /// Registers a PIN-protected secret at the first available generation number.
    pub(crate) async fn register_first_available_generation(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        let register1_requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.register1(realm));

        let mut found_generations: BTreeSet<GenerationNumber> = BTreeSet::new();

        let mut found_errors: Vec<RegisterError> = Vec::new();
        for result in join_all(register1_requests).await {
            match result {
                Ok(generation) => {
                    found_generations.insert(generation);
                }
                Err(e) => self.collect_error(&mut found_errors, e)?,
            }
        }

        let generation = found_generations.last().unwrap().to_owned();

        self.register_generation(generation, pin, secret, policy)
            .await
    }

    fn collect_error(
        &self,
        errors: &mut Vec<RegisterError>,
        error: RegisterError,
    ) -> Result<(), RegisterError> {
        errors.push(error);

        if self.configuration.realms.len() - errors.len()
            < usize::from(self.configuration.register_threshold)
        {
            errors.sort_unstable();
            return Err(errors[0]);
        }

        Ok(())
    }

    /// Registers a PIN-protected secret at a given generation number.
    async fn register_generation(
        &self,
        generation: GenerationNumber,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        let salt = Salt::new_random();
        let hashed_pin = pin
            .hash(&self.configuration.pin_hashing_mode, &salt)
            .ok_or(RegisterError::Assertion)?;

        let oprf_keys: Vec<OprfKey> = std::iter::repeat(())
            .take(self.configuration.realms.len())
            .map(|_| OprfKey::new_random().ok_or(RegisterError::Assertion))
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
            self.register2(
                realm,
                Register2Request {
                    generation,
                    salt: salt.to_owned(),
                    oprf_key,
                    tag: tgk.tag(&realm.public_key),
                    masked_tgk_share,
                    secret_share,
                    policy: policy.to_owned(),
                },
            )
        });

        let mut found_errors = Vec::new();
        for result in join_all(register2_requests).await {
            if let Err(error) = result {
                self.collect_error(&mut found_errors, error)?;
            }
        }
        Ok(())
    }

    /// Executes phase 1 of registration on a particular realm.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn register1(&self, realm: &Realm) -> Result<GenerationNumber, RegisterError> {
        match self.make_request(realm, SecretsRequest::Register1).await {
            Err(RequestError::InvalidAuth) => Err(RegisterError::InvalidAuth),
            Err(RequestError::Assertion) => Err(RegisterError::Assertion),
            Err(RequestError::Transient) => Err(RegisterError::Transient),
            Ok(SecretsResponse::Register1(response)) => Ok(response.next_generation_number),
            Ok(_) => Err(RegisterError::Assertion),
        }
    }

    /// Executes phase 2 of registration on a particular realm at a particular generation.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn register2(
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
            Ok(SecretsResponse::Register2(response)) => match response {
                Register2Response::AlreadyRegistered | Register2Response::BadGeneration => {
                    Err(RegisterError::Assertion)
                }
                Register2Response::Ok => Ok(()),
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
