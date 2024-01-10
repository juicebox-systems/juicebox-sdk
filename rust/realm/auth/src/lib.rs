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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", clap(rename_all = "verbatim"))]
pub enum AuthKeyAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// HMAC using SHA-256
    HS256,
    /// Edwards-curve 25519 Digital Signature Algorithm
    EdDSA,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A symmetric key used for creating and validating JWT tokens
/// for clients (see [`AuthToken`]).
pub struct AuthKey {
    pub data: SecretBytesVec,
    pub algorithm: AuthKeyAlgorithm,
}

#[derive(Debug, Deserialize)]
enum AuthKeyDataEncoding {
    Hex,
    UTF8,
}

#[derive(Debug, Deserialize)]
struct AuthKeyJSON {
    data: String,
    encoding: AuthKeyDataEncoding,
    algorithm: AuthKeyAlgorithm,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthKeyParsingError {
    InvalidDataForEncoding,
    InvalidJSON,
}

impl AuthKey {
    pub fn expose_secret(&self) -> &[u8] {
        self.data.expose_secret()
    }

    pub fn from_json(slice: &[u8]) -> Result<Self, AuthKeyParsingError> {
        if let Ok(json) = serde_json::from_slice::<AuthKeyJSON>(slice) {
            Ok(AuthKey {
                data: match json.encoding {
                    AuthKeyDataEncoding::Hex => match hex::decode(json.data) {
                        Ok(vec) => vec,
                        Err(_) => return Err(AuthKeyParsingError::InvalidDataForEncoding),
                    },
                    AuthKeyDataEncoding::UTF8 => json.data.as_bytes().to_vec(),
                }
                .into(),
                algorithm: json.algorithm,
            })
        } else {
            Err(AuthKeyParsingError::InvalidJSON)
        }
    }
}

impl From<Vec<u8>> for AuthKey {
    fn from(value: Vec<u8>) -> Self {
        Self {
            data: value.into(),
            algorithm: AuthKeyAlgorithm::HS256,
        }
    }
}

impl From<SecretBytesVec> for AuthKey {
    fn from(value: SecretBytesVec) -> Self {
        Self {
            data: value,
            algorithm: AuthKeyAlgorithm::HS256,
        }
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

    use jwt_simple::{
        algorithms::{Ed25519KeyPair, RS256KeyPair},
        prelude::{Audiences, Duration, HS256Key, JWTClaims, MACLike, UnixTimeStamp},
    };

    use super::*;
    use crate::validation::{Error, Require};

    #[test]
    fn test_json_parsing_hs256_utf8() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "UTF8",
            "algorithm": "HS256"
        }
        "#;
        assert_eq!(
            AuthKey::from_json(json.as_bytes()).unwrap(),
            AuthKey {
                data: b"hello world".to_vec().into(),
                algorithm: AuthKeyAlgorithm::HS256
            }
        );
    }

    #[test]
    fn test_json_parsing_eddsa_hex() {
        let json = r#"
        {
            "data": "302e020100300506032b6570042204207c6f273d5ecccf1c01706ccd98a4fb661aac4185edd58c4705c9db9670ef8cdd",
            "encoding": "Hex",
            "algorithm": "EdDSA"
        }
        "#;
        assert_eq!(
            AuthKey::from_json(json.as_bytes()).unwrap(),
            AuthKey {
                data: hex::decode("302e020100300506032b6570042204207c6f273d5ecccf1c01706ccd98a4fb661aac4185edd58c4705c9db9670ef8cdd").unwrap().into(),
                algorithm: AuthKeyAlgorithm::EdDSA
            }
        );
    }

    #[test]
    fn test_json_parsing_invalid_hex() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "Hex",
            "algorithm": "HS256"
        }
        "#;
        assert_eq!(
            AuthKey::from_json(json.as_bytes()).unwrap_err(),
            AuthKeyParsingError::InvalidDataForEncoding
        );
    }

    #[test]
    fn test_json_parsing_invalid_encoding() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "Nope",
            "algorithm": "HS256"
        }
        "#;
        assert_eq!(
            AuthKey::from_json(json.as_bytes()).unwrap_err(),
            AuthKeyParsingError::InvalidJSON
        );
    }

    #[test]
    fn test_json_parsing_invalid_algorithm() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "UTF8",
            "algorithm": "LMNOP"
        }
        "#;
        assert_eq!(
            AuthKey::from_json(json.as_bytes()).unwrap_err(),
            AuthKeyParsingError::InvalidJSON
        );
    }

    #[test]
    fn test_json_parsing_invalid_json() {
        let json = "xyz";
        assert_eq!(
            AuthKey::from_json(json.as_bytes()).unwrap_err(),
            AuthKeyParsingError::InvalidJSON
        );
    }

    #[test]
    fn test_token_hs256() {
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
    fn test_token_rs256() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: Some(Scope::User),
        };
        let key_pair = RS256KeyPair::generate(2048).unwrap();
        let private_key = AuthKey {
            data: key_pair.to_der().unwrap().into(),
            algorithm: AuthKeyAlgorithm::RS256,
        };
        let public_key = AuthKey {
            data: key_pair.public_key().to_der().unwrap().into(),
            algorithm: AuthKeyAlgorithm::RS256,
        };
        let token = creation::create_token(&claims, &private_key, AuthKeyVersion(32));
        let validator = validation::Validator::new(realm_id, Require::Scope(Scope::User));
        assert_eq!(
            validator.parse_key_id(&token).unwrap(),
            (String::from("tenant"), AuthKeyVersion(32))
        );
        assert_eq!(validator.validate(&token, &public_key).unwrap(), claims);
    }

    #[test]
    fn test_token_eddsa() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
            scope: Some(Scope::User),
        };
        let key_pair = Ed25519KeyPair::generate();
        let private_key = AuthKey {
            data: key_pair.to_der().into(),
            algorithm: AuthKeyAlgorithm::EdDSA,
        };
        let public_key = AuthKey {
            data: key_pair.public_key().to_der().into(),
            algorithm: AuthKeyAlgorithm::EdDSA,
        };
        let token = creation::create_token(&claims, &private_key, AuthKeyVersion(32));
        let validator = validation::Validator::new(realm_id, Require::Scope(Scope::User));
        assert_eq!(
            validator.parse_key_id(&token).unwrap(),
            (String::from("tenant"), AuthKeyVersion(32))
        );
        assert_eq!(validator.validate(&token, &public_key).unwrap(), claims);
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
