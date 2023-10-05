//! A trait representing generic management of tokens that grant
//! the authority to act as a particular user on a particular realm.

use async_trait::async_trait;
use juicebox_realm_api::types::{AuthToken, RealmId};
use juicebox_realm_auth::creation::create_token;
use juicebox_realm_auth::{AuthKey, AuthKeyVersion, Claims, Scope};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;

/// A trait representing generic management of tokens that grant
/// the authority to act as a particular user on a particular realm.
#[async_trait]
pub trait AuthTokenManager {
    /// Called when authentication is needed for a given realm.
    /// Ideally, you are reading from tokens you have already
    /// cached locally before making requests. However, if you
    /// do not have a token yet for this realm you can fetch one
    /// now.
    async fn get(&self, realm: &RealmId) -> Option<AuthToken>;
}

/// A trait representing generic management of tokens that grant
/// the authority to act as a particular user on a particular realm.
#[async_trait]
impl AuthTokenManager for HashMap<RealmId, AuthToken> {
    async fn get(&self, realm: &RealmId) -> Option<AuthToken> {
        self.get(realm).cloned()
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct UserId(pub [u8; 16]);

/// An unique identifier for a user used in token generation. This
/// identifier should be persisted and remain consistent for all
/// operations performed for a given user.
impl UserId {
    /// Generates a new id with random data.
    pub fn new_random() -> Self {
        Self(OsRng.gen())
    }
}

impl Debug for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for UserId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s.replace('-', "")).map_err(|_| "failed to decode hex id")?;
        Ok(Self(vec.try_into().map_err(|_| "invalid id length")?))
    }
}

/// A generator used for vending [`AuthToken`]s for a user on device,
/// when a tenant backend service is unavailable to vend tokens.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthTokenGenerator {
    /// The private key to sign a token with. The realm must
    /// have the associated private key for validation.
    #[serde(with = "hex_auth_key")]
    key: AuthKey,
    /// The alphanumeric tenant name that is issuing the token.
    /// This must match the tenant name registered on the realms.
    tenant: String,
    /// The private key version.
    version: AuthKeyVersion,
}

impl AuthTokenGenerator {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("failed to convert generator to json")
    }

    /// Vend a new token for the specified [`RealmId`] and [`UserId`]
    pub fn vend(&self, realm_id: &RealmId, user_id: &UserId) -> AuthToken {
        create_token(
            &Claims {
                issuer: self.tenant.to_owned(),
                subject: hex::encode(user_id.0),
                audience: realm_id.to_owned(),
                scope: Some(Scope::User),
            },
            &self.key,
            self.version,
        )
    }
}

mod hex_auth_key {
    use juicebox_realm_auth::AuthKey;
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    use serde::Deserialize;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AuthKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(AuthKey::from(
            hex::decode(s).map_err(serde::de::Error::custom)?,
        ))
    }

    pub fn serialize<S>(key: &AuthKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use juicebox_realm_api::types::RealmId;
    use juicebox_realm_auth::validation::{Require, Validator};
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_generator_json() {
        let input = r#"{
  "key": "0668e97c5d282a08d4251255541845e2d78b78b9438e1562b51d9cf4e099be53",
  "tenant": "acme",
  "version": 1
}"#;
        println!("input:");
        println!("{input}");

        let generator = AuthTokenGenerator::from_json(input).unwrap();
        println!("parsed:");
        println!("{generator:#?}");

        let serialized = generator.to_json();
        println!("serialized:");
        println!("{serialized}");

        assert_eq!(input, serialized);
    }

    #[test]
    fn test_token_creation() {
        let generator = AuthTokenGenerator::from_json(
            r#"{
            "key": "0668e97c5d282a08d4251255541845e2d78b78b9438e1562b51d9cf4e099be53",
            "tenant": "acme",
            "version": 1
          }"#,
        )
        .unwrap();
        let realm_id = RealmId::new_random(&mut OsRng);
        let token = generator.vend(&realm_id, &UserId::new_random());

        let validator = Validator::new(realm_id, Require::Scope(Scope::User));
        assert!(validator.validate(&token, &generator.key).is_ok());
    }
}
