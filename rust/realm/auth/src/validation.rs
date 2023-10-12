use jwt_simple::{
    prelude::{Audiences, HS256Key, MACLike, VerificationOptions},
    token::Token,
};
use std::{collections::HashSet, str::FromStr};

use super::{AuthKey, AuthKeyVersion, AuthToken, Claims, CustomClaims, Scope};
use juicebox_realm_api::types::RealmId;

#[derive(Debug)]
pub enum Error {
    Jwt(jwt_simple::Error),
    BadKeyId,
    BadAudience,
    BadIssuer,
    BadSubject,
    BadScope,
    LifetimeTooLong,
}

pub struct Validator {
    audience: String,
    // This is exposed to support unit testing.
    pub max_lifetime_seconds: Option<u64>,
    require_scope: Require,
}

pub enum Require {
    /// The provided scope must match this.
    Scope(Scope),
    /// The provided scope must match this, or may be completely missing.
    ScopeOrMissing(Scope),
    /// There are no restrictions on scope.
    AnyScopeOrMissing,
}

pub const MAX_LIFETIME_SECONDS: u64 = 60 * 60 * 24;

impl Validator {
    pub fn new(realm_id: RealmId, require_scope: Require) -> Self {
        Self {
            audience: hex::encode(realm_id.0),
            max_lifetime_seconds: Some(MAX_LIFETIME_SECONDS),
            require_scope,
        }
    }

    pub fn parse_key_id(&self, token: &AuthToken) -> Result<(String, AuthKeyVersion), Error> {
        let header = Token::decode_metadata(token.expose_secret()).map_err(Error::Jwt)?;
        match header.key_id().and_then(parse_key_id) {
            Some((tenant, version)) => Ok((tenant, version)),
            None => Err(Error::BadKeyId),
        }
    }

    pub fn validate(&self, token: &AuthToken, key: &AuthKey) -> Result<Claims, Error> {
        let key = HS256Key::from_bytes(key.expose_secret());

        let options = VerificationOptions {
            allowed_audiences: Some(HashSet::from([self.audience.to_owned()])),
            time_tolerance: None,
            ..Default::default()
        };
        let claims = key
            .verify_token::<CustomClaims>(token.expose_secret(), Some(options))
            .map_err(Error::Jwt)?;

        if let Some(max) = self.max_lifetime_seconds {
            match (claims.invalid_before, claims.expires_at) {
                (Some(nbf), Some(exp)) => {
                    if exp.as_secs() - nbf.as_secs() > max {
                        return Err(Error::LifetimeTooLong);
                    }
                }
                _ => return Err(Error::LifetimeTooLong),
            };
        }

        let Some(issuer) = claims.issuer else {
            return Err(Error::BadIssuer);
        };

        let Some(subject) = claims.subject else {
            return Err(Error::BadSubject);
        };

        let (tenant, _) = self.parse_key_id(token)?;
        if tenant != issuer {
            return Err(Error::BadKeyId);
        }

        let Some(Audiences::AsString(audience)) = claims.audiences else {
            return Err(Error::BadAudience);
        };

        let audience = RealmId(
            hex::decode(audience)
                .map_err(|_| Error::BadAudience)?
                .try_into()
                .map_err(|_| Error::BadAudience)?,
        );
        let scope = match claims.custom.scope {
            Some(scopes) => Scope::from_str(&scopes)
                .map_err(|_| Error::BadScope)
                .map(Some),
            None => Ok(None),
        }?;
        match (&scope, &self.require_scope) {
            (None, Require::Scope(_)) => return Err(Error::BadScope),
            (None, Require::ScopeOrMissing(_)) => {}
            (_, Require::AnyScopeOrMissing) => {}
            (Some(actual), Require::Scope(req)) => {
                if actual != req {
                    return Err(Error::BadScope);
                }
            }
            (Some(actual), Require::ScopeOrMissing(req)) => {
                if actual != req {
                    return Err(Error::BadScope);
                }
            }
        }

        Ok(Claims {
            issuer,
            subject,
            audience,
            scope,
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
