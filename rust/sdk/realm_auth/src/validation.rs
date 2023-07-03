use jsonwebtoken::{self, Algorithm, DecodingKey, TokenData, Validation};
use juicebox_sdk_core::types::RealmId;
use serde::Deserialize;

use super::{AuthKey, AuthKeyVersion, AuthToken, Claims};

#[derive(Debug, Deserialize)]
struct InternalClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64, // seconds since Unix epoch
    nbf: u64, // seconds since Unix epoch
}

#[derive(Debug)]
pub enum Error {
    Jwt(jsonwebtoken::errors::Error),
    LifetimeTooLong,
    BadKeyId,
    BadAudience,
}

pub struct Validator {
    validation: Validation,
    // This is exposed to support unit testing.
    pub max_lifetime_seconds: Option<u64>,
}

pub const MAX_LIFETIME_SECONDS: u64 = 60 * 60 * 24;

impl Validator {
    pub fn new(realm_id: RealmId) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[hex::encode(realm_id.0)]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        Self {
            validation,
            max_lifetime_seconds: Some(MAX_LIFETIME_SECONDS),
        }
    }

    pub fn parse_key_id(&self, token: &AuthToken) -> Result<(String, AuthKeyVersion), Error> {
        let header = jsonwebtoken::decode_header(token.0.expose_secret()).map_err(Error::Jwt)?;
        match header.kid.as_deref().and_then(parse_key_id) {
            Some((tenant, version)) => Ok((tenant, version)),
            None => Err(Error::BadKeyId),
        }
    }

    pub fn validate(&self, token: &AuthToken, key: &AuthKey) -> Result<Claims, Error> {
        let key = DecodingKey::from_secret(key.expose_secret());

        let TokenData { header, claims } =
            jsonwebtoken::decode::<InternalClaims>(token.expose_secret(), &key, &self.validation)
                .map_err(Error::Jwt)?;

        if header
            .kid
            .as_deref()
            .and_then(parse_key_id)
            .filter(|(tenant, _version)| tenant == &claims.iss)
            .is_none()
        {
            return Err(Error::BadKeyId);
        }

        if let Some(max) = self.max_lifetime_seconds {
            if claims.exp - claims.nbf > max {
                return Err(Error::LifetimeTooLong);
            }
        }

        let Some(audience) = hex::decode(claims.aud).ok() else {
            return Err(Error::BadAudience);
        };

        let realm_id = RealmId(audience.try_into().map_err(|_| Error::BadAudience)?);

        Ok(Claims {
            issuer: claims.iss,
            subject: claims.sub,
            audience: realm_id,
        })
    }
}

/// Returns tenant and version.
fn parse_key_id(key_id: &str) -> Option<(String, AuthKeyVersion)> {
    let (tenant, version) = key_id.split_once(':')?;
    let version = version.parse::<u64>().ok()?;
    Some((tenant.to_owned(), AuthKeyVersion(version)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_id() {
        assert_eq!(
            parse_key_id("acme:99"),
            Some((String::from("acme"), AuthKeyVersion(99)))
        );
        assert_eq!(parse_key_id("acme-99"), None);
        assert_eq!(parse_key_id("tenant-acme"), None);
        assert_eq!(parse_key_id("tenant-acme:latest"), None);
    }
}
