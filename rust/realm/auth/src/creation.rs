use jwt_simple::prelude::{Duration, HS256Key, MACLike};
use regex::Regex;

use super::{AuthKey, AuthKeyVersion, AuthToken, Claims, CustomClaims};

pub fn create_token(claims: &Claims, key: &AuthKey, key_version: AuthKeyVersion) -> AuthToken {
    let issuer_regex = Regex::new(r"^(test-)?[a-zA-Z0-9]+$").unwrap();
    assert!(
        issuer_regex.is_match(&claims.issuer),
        "tenant names must be alphanumeric. found {:?}",
        claims.issuer,
    );

    let key = HS256Key::from_bytes(key.expose_secret())
        .with_key_id(&format!("{}:{}", claims.issuer, key_version.0));

    let claims = jwt_simple::claims::Claims::with_custom_claims(
        CustomClaims {
            scope: claims.scope.map(|s| s.to_string()),
        },
        Duration::from_mins(10),
    )
    .with_audience(hex::encode(claims.audience.0))
    .with_issuer(&claims.issuer)
    .with_subject(&claims.subject);

    AuthToken::from(key.authenticate(claims).expect("failed to mint token"))
}
