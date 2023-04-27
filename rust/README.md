## Rust

Register and recover PIN-protected secrets on behalf of a particular user.

[Documentation](http://34.160.204.87/rust/loam_sdk/)

### Install

Run the following Cargo command in your project directory:

```
cargo add loam_sdk
```

Or add the following line to your Cargo.toml:

```
loam_sdk = "0.0.1"
```

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth token should be acquired out-of-band from a server you run, and that has communicated to the configured `Realm`s who a valid user is.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```rust
use loam_sdk:*;

let client = Client::new(
    Configuration {
        realms: vec![
            // You should receive the realm parameters from your realm provider,
            // or configure them yourself for your self-hosted realm.
            Realm {
                address: Url::from_str("https://some/realm/address").unwrap(),
                public_key: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
                id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            }
        ],
        register_threshold: 1,
        recover_threshold: 1,
        pin_hashing_mode: PinHashingMode::Standard2019
    },
    vec![],
    auth_token
)
```

If you haven't enabled the `reqwest` or `tokio` feature, you may also need to specify an `http::Client` and a `Sleeper` appropriate for your configuration.

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

And when you're ready to delete all secrets from remote store, simply call:

```rust
client.delete_all().await.unwrap();
```
