use std::process::exit;

use juicebox_realm_api::types::{AuthToken, RealmId, SecretBytesVec};
use juicebox_realm_auth::{
    creation::create_token,
    validation::{Error, Require, Validator, MAX_LIFETIME_SECONDS},
    AuthKey, AuthKeyAlgorithm, AuthKeyVersion, Claims, Scope,
};

use clap::{command, Parser, Subcommand};
use jwt_simple::{
    algorithms::{Ed25519KeyPair, HS256Key, RS256KeyPair},
    JWTError,
};

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
        #[arg(short, long)]
        user: String,
        /// An alphanumeric tenant ID.
        #[arg(short, long)]
        tenant: String,
        /// The ID of the realm, as a hex string, that the token should be valid for.
        #[arg(short, long)]
        realm: RealmId,
        /// The key, as a hex string, that the token should be signed with.
        #[arg(short, long, value_parser = parse_auth_key)]
        key: SecretBytesVec,
        /// The integer version of the signing key.
        #[arg(short, long, value_parser = parse_auth_key_version)]
        version: AuthKeyVersion,
        /// The algorithm of the signing key.
        #[arg(short, long, value_enum)]
        algorithm: AuthKeyAlgorithm,
        /// The scope to include in the token.
        #[arg(short, long, default_value_t)]
        scope: Scope,
    },

    /// Validate an auth token for a tenant.
    Validate {
        /// The jwt token to validate.
        #[arg(short('j'), long)]
        token: AuthToken,
        /// The alphanumeric user ID that this token was created with.
        #[arg(short, long)]
        user: String,
        /// The alphanumeric tenant ID that this token was created with.
        #[arg(short, long)]
        tenant: String,
        /// The ID of the realm, as a hex string, that the token was made valid for.
        #[arg(short, long)]
        realm: RealmId,
        /// The key, as a hex string, that the token was signed with.
        #[arg(short, long, value_parser = parse_auth_key)]
        key: SecretBytesVec,
        /// The integer version of the signing key.
        #[arg(short, long, value_parser = parse_auth_key_version)]
        version: AuthKeyVersion,
        /// The algorithm of the signing key.
        #[arg(short, long, value_enum)]
        algorithm: AuthKeyAlgorithm,
    },

    /// Create a random key (or key pair) for a tenant and output to stdout.
    Random {
        /// The algorithm of the signing key.
        #[arg(short, long, value_enum)]
        algorithm: AuthKeyAlgorithm,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::Create {
            user,
            tenant,
            realm,
            key,
            version,
            algorithm,
            scope,
        } => {
            let token = create_token(
                &Claims {
                    issuer: tenant,
                    subject: user,
                    audience: realm,
                    scope: Some(scope),
                },
                &AuthKey {
                    data: key,
                    algorithm,
                },
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
            algorithm,
        } => {
            let mut errors: Vec<String> = vec![];
            let mut warnings: Vec<String> = vec![];

            let validator = Validator::new(realm, Require::AnyScopeOrMissing);

            match validator.validate(&token, &AuthKey { data: key, algorithm }) {
                Ok(Claims {
                    issuer,
                    subject,
                    audience: _,
                    scope,
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
                    if scope.is_none() {
                        warnings.push(format!("no 'scope' supplied in token. \
                        A scope (one of {}) will soon be required.", Scope::strings().join(", ")))
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
                Err(Error::BadScope) => errors.push(
                    format!("provided scope is not valid or missing. Should be one of {}", Scope::strings().join(", "))
                ),
                Err(Error::BadIssuer) => errors.push(
                    format!("provided issuer is not valid or missing. Should be {}", tenant)
                ),
                Err(Error::BadSubject) => errors.push(
                    format!("provided subject is not valid or missing. Should be {}", user)
                ),
                Err(Error::Jwt(e)) => match e.downcast::<JWTError>() {
                    Ok(JWTError::NotJWT) => errors.push(
                        "provided token does not have valid jwt shape, is it a jwt?".to_string(),
                    ),
                    Ok(JWTError::InvalidSignature) => {
                        errors.push("token signed with incorrect key".to_string())
                    }
                    Ok(JWTError::TokenHasExpired) => errors.push(
                        "token has expired, verify the `exp` field in your `claims`.".to_string(),
                    ),
                    Ok(JWTError::TokenNotValidYet) => errors.push(
                        "token not yet valid, verify the `nbf` field in your `claims`.".to_string(),
                    ),
                    Ok(JWTError::RequiredAudienceMismatch) => errors.push(format!(
                        "invalid `aud` in `claims`. (expected `aud` of {})",
                        hex::encode(realm.0)
                    )),
                    Ok(JWTError::AlgorithmMismatch) => errors.push("invalid `algorithm` in `header`. verify you are using HS256 to sign your token.".to_string()),
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
        Command::Random { algorithm } => match algorithm {
            AuthKeyAlgorithm::HS256 => {
                println!("{}", hex::encode(HS256Key::generate().to_bytes()));
            }
            AuthKeyAlgorithm::RS256 => {
                let key_pair = RS256KeyPair::generate(4096).expect("failed to generate key pair");
                println!("private key: {}", hex::encode(key_pair.to_der().unwrap()));
                println!(
                    "public key: {}",
                    hex::encode(key_pair.public_key().to_der().unwrap())
                );
            }
            AuthKeyAlgorithm::EdDSA => {
                let key_pair = Ed25519KeyPair::generate();
                println!("private key: {}", hex::encode(key_pair.to_der()));
                println!(
                    "public key: {}",
                    hex::encode(key_pair.public_key().to_der())
                );
            }
        },
    };
}

fn parse_auth_key(buf: &str) -> Result<SecretBytesVec, hex::FromHexError> {
    let key = hex::decode(buf)?;
    Ok(key.into())
}

fn parse_auth_key_version(buf: &str) -> Result<AuthKeyVersion, std::num::ParseIntError> {
    Ok(AuthKeyVersion(buf.parse()?))
}
