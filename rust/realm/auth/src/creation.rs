use jwt_simple::{
    algorithms::{Ed25519KeyPair, EdDSAKeyPairLike, RS256KeyPair, RSAKeyPairLike},
    prelude::{Duration, HS256Key, MACLike},
};
use regex::Regex;

use super::{AuthKey, AuthKeyAlgorithm, AuthKeyVersion, AuthToken, Claims, CustomClaims};

pub fn create_token(claims: &Claims, key: &AuthKey, key_version: AuthKeyVersion) -> AuthToken {
    let issuer_regex = Regex::new(r"^(test-)?[a-zA-Z0-9]+$").unwrap();
    assert!(
        issuer_regex.is_match(&claims.issuer),
        "tenant names must be alphanumeric. found {:?}",
        claims.issuer,
    );

    let jwt_claims = jwt_simple::claims::Claims::with_custom_claims(
        CustomClaims {
            scope: claims.scope.map(|s| s.to_string()),
        },
        Duration::from_mins(10),
    )
    .with_audience(hex::encode(claims.audience.0))
    .with_issuer(&claims.issuer)
    .with_subject(&claims.subject);

    let key_id = format!("{}:{}", claims.issuer, key_version.0);

    AuthToken::from(match key.algorithm {
        AuthKeyAlgorithm::EdDSA => {
            let key_pair = Ed25519KeyPair::from_der(key.expose_secret())
                .expect("failed to parse ed25519 private key")
                .with_key_id(&key_id);
            key_pair.sign(jwt_claims).expect("failed to sign token")
        }
        AuthKeyAlgorithm::RS256 => {
            let key_pair = RS256KeyPair::from_der(key.expose_secret())
                .expect("failed to parse rs256 private key")
                .with_key_id(&key_id);
            key_pair.sign(jwt_claims).expect("failed to sign token")
        }
        AuthKeyAlgorithm::HS256 => {
            let key = HS256Key::from_bytes(key.expose_secret()).with_key_id(&key_id);
            key.authenticate(jwt_claims)
                .expect("failed to authenticate token")
        }
    })
}
