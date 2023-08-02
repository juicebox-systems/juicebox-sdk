use jsonwebtoken::{self, get_current_timestamp, Algorithm, EncodingKey, Header};
use regex::Regex;
use serde::Serialize;

use super::{AuthKey, AuthKeyVersion, AuthToken, Claims};

#[derive(Serialize)]
pub(super) struct InternalClaims<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub exp: u64, // seconds since Unix epoch
    pub nbf: u64, // seconds since Unix epoch
}

pub fn create_token(claims: &Claims, key: &AuthKey, key_version: AuthKeyVersion) -> AuthToken {
    create_token_at(claims, key, key_version, get_current_timestamp())
}

// split from `create_token` for testing
pub(super) fn create_token_at(
    claims: &Claims,
    key: &AuthKey,
    key_version: AuthKeyVersion,
    now: u64,
) -> AuthToken {
    let mut header = Header::new(Algorithm::HS256);
    let issuer_regex = Regex::new(r"^(test-)?[a-zA-Z0-9]+$").unwrap();
    assert!(
        issuer_regex.is_match(&claims.issuer),
        "tenant names must be alphanumeric. found {:?}",
        claims.issuer,
    );
    header.kid = Some(format!("{}:{}", claims.issuer, key_version.0));
    AuthToken::from(
        jsonwebtoken::encode(
            &header,
            &InternalClaims {
                iss: &claims.issuer,
                sub: &claims.subject,
                aud: &hex::encode(claims.audience.0),
                exp: now + 60 * 10,
                nbf: now - 10,
            },
            &EncodingKey::from_secret(key.expose_secret()),
        )
        .expect("failed to mint token"),
    )
}
