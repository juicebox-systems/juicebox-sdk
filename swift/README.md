## Swift

Register and recover PIN-protected secrets on behalf of a particular user.

[Documentation](https://docs.juicebox.xyz/swift/documentation/juiceboxsdk/)

### Install

This library wraps a Rust FFI layer. To use it, you must [install rust](https://www.rust-lang.org/tools/install) and the appropriate targets:

```sh
rustup toolchain install 1.75 --profile minimal
rustup default 1.75
rustup target add x86_64-apple-ios aarch64-apple-ios aarch64-apple-ios-sim
```

#### Cocoa Pods

Run the following command in your project directory:

```sh
pod install JuiceboxSdk
```

**_Note:_** You may wish to use [cocoapods-binary](https://guides.cocoapods.org/plugins/pre-compiling-dependencies.html) to persist the compiled Rust artifacts in your `Pods` folder. This allows building your project without requiring Rust be installed after the initial `pod install`.

#### Swift Package

See the [demo](demo) project in this repository for an example.

**_Note:_** because there are native dependencies, you will need to clone this repo, build the dependencies (running `swift/ffi.sh`), and set your linker settings appropriately.

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth tokens should be acquired out-of-band from a server you run and specific to each realm id. All of the realms must be set up to accept this server's tokens. You can either provide a map of tokens that are valid for the lifetime of the client or implement the `Client.fetchAuthTokenCallback` to dynamically fetch tokens as necessary.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```swift
import JuiceboxSdk

let client = Client(
    configuration: .init(
        // You should receive the realm parameters from your realm provider,
        // or configure them yourself for your self-hosted realm.
        json: """
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
        """
    ),
    authTokens: [
        RealmId(string: "0102030405060708090a0b0c0d0e0f10")!: authToken1,
        RealmId(string: "2102030405060708090a0b0c0d0e0f10")!: authToken2,
        RealmId(string: "3102030405060708090a0b0c0d0e0f10")!: authToken3
    ]
)
```

Once you've created a client, you can register a secret for the `authToken`'s user by calling:

```swift
try await client.register(
    pin: "1234".data(using: .utf8)!,
    secret: "secret".data(using: .utf8)!,
    info: "info".data(using: .utf8)!,
    guesses: 5
)
```

To recover the secret you just registered, you can call:

```swift
let secret = try await client.recover(
    pin: "1234".data(using: .utf8)!,
    info: "info".data(using: .utf8)!
)
```

And when you're ready to delete any secret from the remote store, simply call:

```swift
try await client.delete()
```
