use std::process::exit;

use jsonwebtoken::errors::ErrorKind;
use juicebox_sdk_core::types::{AuthToken, RealmId};
use juicebox_sdk_realm_auth::{
    creation::create_token,
    validation::{Error, Validator, MAX_LIFETIME_SECONDS},
    AuthKey, AuthKeyVersion, Claims,
};

use clap::{command, Parser, Subcommand};

/// A CLI tool for validation and creation of auth tokens.
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an auth token for a tenant.
    Create {
        /// An alphanumeric user ID that this token should be valid for.
        user: String,
        /// An alphanumeric tenant ID.
        tenant: String,
        /// The ID of the realm, as a hex string, that the token should be valid for.
        realm: RealmId,
        /// The key, as a hex string, that the token should be signed with.
        #[arg(value_parser = parse_auth_key)]
        key: AuthKey,
        /// The integer version of the signing key.
        #[arg(value_parser = parse_auth_key_version)]
        version: AuthKeyVersion,
    },

    /// Validate an auth token for a tenant.
    Validate {
        /// The token to validate.
        token: AuthToken,
        /// The alphanumeric user ID that this token was created with.
        user: String,
        /// The alphanumeric tenant ID that this token was created with.
        tenant: String,
        /// The ID of the realm, as a hex string, that the token was made valid for.
        realm: RealmId,
        /// The key, as a hex string, that the token was signed with.
        #[arg(value_parser = parse_auth_key)]
        key: AuthKey,
        /// The integer version of the signing key.
        #[arg(value_parser = parse_auth_key_version)]
        version: AuthKeyVersion,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match args.command {
        Command::Create {
            user,
            tenant,
            realm,
            key,
            version,
        } => {
            let token = create_token(
                &Claims {
                    issuer: tenant,
                    subject: user,
                    audience: realm,
                },
                &key,
                version,
            );
            println!("{}", token.expose_secret());
        }
        Command::Validate {
            token,
            user,
            tenant,
            realm,
            key,
            version,
        } => {
            let mut errors: Vec<String> = vec![];
            let mut warnings: Vec<String> = vec![];

            let validator = Validator::new(realm);

            match validator.validate(&token, &key) {
                Ok(Claims {
                    issuer,
                    subject,
                    audience: _,
                }) => {
                    if issuer != tenant {
                        warnings.push(format!(
                            "unexpected `iss` in `claims` ({} != {})",
                            issuer, tenant
                        ));
                    }
                    if subject != user {
                        warnings.push(format!(
                            "unexpected `sub` in `claims` ({} != {})",
                            subject, user
                        ));
                    }
                }
                Err(Error::BadKeyId) => {
                    // checked below
                }
                Err(Error::LifetimeTooLong) => errors.push(format!(
                    "invalid `nbf` and `exp`. `exp` - `nbf` must be <= {}",
                    MAX_LIFETIME_SECONDS
                )),
                Err(Error::BadAudience) => errors.push(
                    "unable to parse `aud` in `claims`. verify your `aud` is a string of hex bytes"
                        .to_string(),
                ),
                Err(Error::Jwt(e)) => match e.into_kind() {
                    ErrorKind::InvalidToken => errors.push(
                        "provided token does not have valid jwt shape, is it a jwt?".to_string(),
                    ),
                    ErrorKind::InvalidSignature => {
                        errors.push("token signed with incorrect key".to_string())
                    }
                    ErrorKind::ExpiredSignature => errors.push(
                        "token has expired, verify the `exp` field in your `claims`.".to_string(),
                    ),
                    ErrorKind::ImmatureSignature => errors.push(
                        "token not yet valid, verify the `nbf` field in your `claims`.".to_string(),
                    ),
                    ErrorKind::InvalidAudience => errors.push(format!(
                        "invalid `aud` in `claims`. (expected `aud` of {})",
                        hex::encode(realm.0)
                    )),
                    ErrorKind::MissingRequiredClaim(claim) => {
                        errors.push(format!("missing `{}` in `claims`", claim))
                    }
                    ErrorKind::InvalidAlgorithm => errors.push("invalid `algorithm` in `header`. verify you are using HS256 to sign your token.".to_string()),
                    e => errors.push(format!("unexpected issuer parsing jwt {:?}", e)),
                },
            }

            match validator.parse_key_id(&token) {
                Ok((t, v)) => {
                    if t != tenant {
                        warnings.push(format!(
                            "unexpected `tenant` in `kid` ({} != {})",
                            t, tenant
                        ));
                    }
                    if v != version {
                        warnings.push(format!(
                            "unexpected `version` in `kid` ({} != {})",
                            v.0, version.0
                        ));
                    }
                }
                Err(_) => {
                    errors.push("invalid `kid` not in the format of `tenant:version`".to_string())
                }
            };

            for error in &errors {
                eprintln!("ERROR: {}", error);
            }

            for warning in warnings {
                println!("WARNING: {}", warning);
            }

            if errors.is_empty() {
                println!("Token is valid!");
            } else {
                exit(1);
            }
        }
    };
}

fn parse_auth_key(buf: &str) -> Result<AuthKey, hex::FromHexError> {
    let key = hex::decode(buf)?;
    Ok(AuthKey::from(key))
}

fn parse_auth_key_version(buf: &str) -> Result<AuthKeyVersion, std::num::ParseIntError> {
    Ok(AuthKeyVersion(buf.parse()?))
}
