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

The auth token should be acquired out-of-band from a server you run. All of the realms must be set up to accept this server's tokens.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```swift
import LoamSdk

let client = Client(
    configuration: .init(
        realms: [
            // You should receive the realm parameters from your realm provider,
            // or configure them yourself for your self-hosted realm.
            .init(
                id: UUID(uuidString: "01020304-0506-0708-090A-0B0C0D0E0F10")!,
                address: URL(string: "https://some/realm/address1")!,
                publicKey: Data(base64Encoded: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".data(using: .utf8)!)!
            ),
            .init(
                id: UUID(uuidString: "10010203-0405-0607-0809-0A0B0C0D0E0F")!,
                address: URL(string: "https://some/realm/address2")!,
                publicKey: Data(base64Encoded: "IB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE=".data(using: .utf8)!)!
            )
        ],
        registerThreshold: 2,
        recoverThreshold: 2,
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
