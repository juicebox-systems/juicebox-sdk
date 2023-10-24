use std::fmt::Display;
use std::str::FromStr;

use juicebox_realm_api::types::{AuthToken, RealmId, SecretBytesVec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod creation;
pub mod validation;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// An integer version for an [`AuthKey`] secret.
pub struct AuthKeyVersion(pub u64);

#[derive(Clone, Debug)]
/// A symmetric key used for creating and validating JWT tokens
/// for clients (see [`AuthToken`]).
pub struct AuthKey(pub SecretBytesVec);

impl AuthKey {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for AuthKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CustomClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// The data from an [`AuthToken`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claims {
    /// Tenant ID.
    pub issuer: String,
    /// User ID.
    pub subject: String,
    /// Realm ID.
    pub audience: RealmId,
    /// Scope. see https://www.rfc-editor.org/rfc/rfc8693.html Although scopes
    /// is a list we only support having a single scope set. Scope is currently
    /// optional, but will be required in the future.
    pub scope: Option<Scope>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Scope {
    #[default]
    User,
    Audit,
}

impl Scope {
    pub fn strings() -> Vec<String> {
        vec![Scope::User.to_string(), Scope::Audit.to_string()]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Audit => "audit",
        }
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = ScopeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "audit" => Ok(Scope::Audit),
            "user" => Ok(Scope::User),
            _ => Err(ScopeParseError),
        }
    }
}

#[derive(Debug, Error)]
#[error("invalid scope value")]
pub struct ScopeParseError;

#[cfg(test)]
mod tests {

    use jwt_simple::prelude::{Audiences, Duration, HS256Key, JWTClaims, MACLike, UnixTimeStamp};

    use super::*;
    use crate::validation::{Error, Require};

    #[test]
    fn test_token_basic() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: Some(Scope::User),
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, AuthKeyVersion(32));
        let validator = validation::Validator::new(realm_id, Require::Scope(Scope::User));
        assert_eq!(
            validator.parse_key_id(&token).unwrap(),
            (String::from("tenant"), AuthKeyVersion(32))
        );
        assert_eq!(validator.validate(&token, &key).unwrap(), claims);
    }

    #[test]
    fn test_token_scope() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: Some(Scope::Audit),
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, AuthKeyVersion(32));
        let validator = validation::Validator::new(realm_id, Require::Scope(Scope::Audit));
        assert_eq!(validator.validate(&token, &key).unwrap(), claims);

        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: Some(Scope::User),
        };
        let token = creation::create_token(&claims, &key, AuthKeyVersion(32));
        assert!(matches!(
            validator.validate(&token, &key),
            Err(Error::BadScope)
        ));

        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: None,
        };
        let token = creation::create_token(&claims, &key, AuthKeyVersion(32));
        assert!(matches!(
            validator.validate(&token, &key),
            Err(Error::BadScope)
        ));

        let validator = validation::Validator::new(realm_id, Require::ScopeOrMissing(Scope::Audit));
        assert_eq!(validator.validate(&token, &key).unwrap(), claims);
    }

    #[test]
    fn test_bad_scope() {
        let realm_id = RealmId([5; 16]);
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let mint = |scope| {
            let key = HS256Key::from_bytes(key.expose_secret()).with_key_id("tenant:1");
            let claims = jwt_simple::claims::Claims::with_custom_claims(
                CustomClaims { scope },
                Duration::from_mins(10),
            )
            .with_audience(hex::encode(realm_id.0))
            .with_subject("mario")
            .with_issuer("tenant");

            AuthToken::from(key.authenticate(claims).unwrap())
        };

        let validator = validation::Validator::new(realm_id, Require::ScopeOrMissing(Scope::User));
        assert!(matches!(
            validator.validate(&mint(Some("auditor".to_string())), &key),
            Err(Error::BadScope)
        ));
    }

    #[test]
    fn test_token_bogus() {
        let realm_id = RealmId([5; 16]);
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = AuthToken::from(String::from("bogus"));
        assert_eq!(
            format!(
                "{:?}",
                validation::Validator::new(realm_id, Require::ScopeOrMissing(Scope::User))
                    .validate(&token, &key)
                    .unwrap_err()
            ),
            "Jwt(JWT compact encoding error)"
        );
    }

    #[test]
    fn test_token_expired() {
        let realm_id = RealmId([5; 16]);
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let past = UnixTimeStamp::from_u64(1400);
        let claims = JWTClaims {
            issued_at: Some(past),
            expires_at: Some(past + Duration::from_mins(10)),
            invalid_before: Some(past),
            audiences: Some(Audiences::AsString(hex::encode(realm_id.0))),
            issuer: Some("tenant".to_string()),
            jwt_id: None,
            subject: Some("mario".to_string()),
            nonce: None,
            custom: CustomClaims {
                scope: Some(Scope::User.to_string()),
            },
        };

        let token = AuthToken::from(
            HS256Key::from_bytes(key.expose_secret())
                .with_key_id("tenant:1")
                .authenticate(claims)
                .unwrap(),
        );

        assert_eq!(
            format!(
                "{:?}",
                validation::Validator::new(realm_id, Require::Scope(Scope::User))
                    .validate(&token, &key)
                    .unwrap_err()
            ),
            "Jwt(Token has expired)"
        );
    }

    #[test]
    fn test_token_lifetime_too_long() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: Some(Scope::User),
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, AuthKeyVersion(32));
        let mut validator = validation::Validator::new(realm_id, Require::Scope(Scope::User));
        validator.max_lifetime_seconds = Some(5);
        assert!(matches!(
            validator.validate(&token, &key),
            Err(Error::LifetimeTooLong),
        ));
        validator.max_lifetime_seconds = None;
        assert!(validator.validate(&token, &key).is_ok());
    }

    #[test]
    fn test_token_wrong_audience() {
        let realm_id_token = RealmId([5; 16]);
        let realm_id_validator = RealmId([1; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id_token,
            scope: Some(Scope::User),
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, AuthKeyVersion(32));
        let validator = validation::Validator::new(realm_id_validator, Require::Scope(Scope::User));
        assert_eq!(
            format!("{:?}", validator.validate(&token, &key).unwrap_err()),
            "Jwt(Required audience mismatch)"
        );
    }

    #[test]
    fn test_token_bad_key_id() {
        let realm_id = RealmId([5; 16]);
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let mint = |key_id| {
            let key = HS256Key::from_bytes(key.expose_secret()).with_key_id(key_id);
            let claims = jwt_simple::claims::Claims::create(Duration::from_mins(10))
                .with_audience(hex::encode(realm_id.0))
                .with_subject("mario")
                .with_issuer("tenant");

            AuthToken::from(key.authenticate(claims).unwrap())
        };

        let validator = validation::Validator::new(realm_id, Require::AnyScopeOrMissing);
        validator.validate(&mint("tenant:32"), &key).unwrap();
        assert!(matches!(
            validator.validate(&mint("ten:ant:32"), &key),
            Err(Error::BadKeyId),
        ));
        assert!(matches!(
            validator.validate(&mint("antenna:32"), &key),
            Err(Error::BadKeyId),
        ));
        assert!(matches!(
            validator.validate(&mint("tenant:latest"), &key),
            Err(Error::BadKeyId),
        ));
        assert!(matches!(
            validator.validate(&mint("tenant:"), &key),
            Err(Error::BadKeyId),
        ));
        assert!(matches!(
            validator.validate(&mint("some-non-alphanumerics:2"), &key),
            Err(Error::BadKeyId),
        ));
    }
}
