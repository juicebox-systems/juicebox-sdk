## Swift

Register and recover PIN-protected secrets on behalf of a particular user.

[Documentation](http://34.160.204.87/swift/documentation/loamsdk/)

### Install

#### Cocoa Pods

Run the following command in your project directory:

```
pod install LoamSdk
```

#### Swift Package

See the [demo](demo) project in this respository for an example.

Note: because there are native dependencies, you will need to clone
this repo, build the dependencies (running `ffi.sh`), and set your
linker settings appropriately.

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth token should be acquired out-of-band from a server you run, and that has communicated to the configured `Realm`s who a valid user is.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```swift
import LoamSdk

let client = Client(
    configuration: .init(
        realms: [
            // You should receive the realm parameters from your realm provider,
            // or configure them yourself for your self-hosted realm.
            .init(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000000")!,
                address: URL(string: "https://some/realm/address")!,
                publicKey: Data(base64Encoded: "YXJ0ZW1pcw".data(using: .utf8)!)!
            )
        ],
        registerThreshold: 1,
        recoverThreshold: 1,
        pinHashingMode: .standard2019
    ),
    authToken: authToken
)
```

Once you've created a client, you can register a secret for the `authToken`'s user by calling:

```swift
try await client.register(
    pin: "1234".data(using: .utf8)!,
    secret: "secret".data(using: .utf8)!,
    guesses: 5
)
```

To recover the secret you just registered, you can call:

```swift
let secret = try await client.recover(
    pin: "1234".data(using: .utf8)!
)
```

And when you're ready to delete all secrets from remote store, simply call:

```swift
try await client.deleteAll()
```
