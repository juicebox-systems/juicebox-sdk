## Rust

Register and recover PIN-protected secrets on behalf of a particular user.

[Documentation](https://docs.juicebox.xyz/rust/juicebox_sdk/)

### Install

Run the following Cargo command in your project directory:

```
cargo add juicebox-sdk
```

Or add the following line to your Cargo.toml:

```
juicebox-sdk = "0.0.1"
```

Additionally, you may wish to enable the `tokio` or `reqwest` [features](#features) to simplify usage:

```
juicebox-sdk = { version = "0.0.1", features = ["tokio", "reqwest"] }
```

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth tokens should be acquired out-of-band from a server you run and specific to each realm id. All of the realms must be set up to accept this server's tokens. You can either provide a map of tokens that are valid for the lifetime of the client or implement the `AuthTokenManager` trait to dynamically fetch tokens as necessary.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```rust
use juicebox_sdk:{Client, Configuration, Realm, PinHashingMode};
use hex_literal::hex;
use url::Url;

// You should receive the realm parameters from your realm provider,
// or configure them yourself for your self-hosted realm.
let configuration = Configuration::from_json(r#"
{
  "realms": [
    {
      "address": "https://juicebox.hsm.realm.address",
      "id": "0102030405060708090a0b0c0d0e0f10",
      "public_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    },
    {
      "address": "https://your.software.realm.address",
      "id": "2102030405060708090a0b0c0d0e0f10"
    },
    {
      "address": "https://juicebox.software.realm.address",
      "id": "3102030405060708090a0b0c0d0e0f10"
    }
  ],
  "register_threshold": 3,
  "recover_threshold": 3,
  "pin_hashing_mode": "Standard2019"
}
"#).expect("failed to parse configuration json");

let client = Client::with_tokio(
    configuration,
    vec![],
    vec![
        ("0102030405060708090a0b0c0d0e0f10".parse().expect("invalid realm id"), authToken1),
        ("2102030405060708090a0b0c0d0e0f10".parse().expect("invalid realm id"), authToken2),
        ("3102030405060708090a0b0c0d0e0f10".parse().expect("invalid realm id"), authToken3)
    ].iter().collect()
)
```

If you haven't enabled the `reqwest` or `tokio` feature, you also need to specify an `http::Client` and a `Sleeper` appropriate for your configuration.

Once you've created a client, you can register a secret for the `auth_token`'s user by calling:

```rust
client.register(
    &Pin::from(b"1234".to_vec()),
    &UserSecret::from(b"secret".to_vec()),
    Policy { num_guesses: 5 },
).await.unwrap();
```

To recover the secret you just registered, you can call:

```rust
let secret = client.recover(
    &Pin::from(b"1234".to_vec()),
).await.unwrap();
```

And when you're ready to delete any secret from the remote store, simply call:

```rust
client.delete().await.unwrap();
```

### Features
* The `tokio` feature requires the `tokio` crate in order to provide async `sleep` functionality.
* The `reqwest` feature requires the `reqwest` crate in order to execute HTTP requests.
