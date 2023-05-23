## Android

Register and recover PIN-protected secrets on behalf of a particular user.

[Documentation](http://34.160.204.87/android/loam-sdk/me.loam.sdk/)

### Install

#### Gradle

```
repositories {
  google()
  mavenCentral()
}

dependencies {
  implementation 'com.github.loam-security.loam-sdk:loam-sdk:0.0.1'
}
```

#### Maven

```
<dependency>
  <groupId>com.github.loam-security.loam-sdk</groupId>
  <artifactId>loam-sdk</artifactId>
  <version>0.0.1</version>
</dependency>
```

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth tokens should be acquired out-of-band from a server you run and specific to each realm id. All of the realms must be set up to accept this server's tokens. You can either provide a map of tokens that are valid for the lifetime of the client or implement the `Client.fetchAuthTokenCallback` to dynamically fetch tokens as necessary.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```kotlin
import me.loam.sdk.*
import java.util.Base64

val decoder = Base64.getDecoder()

val client = Client(
                Configuration(
                    // You should receive the realm parameters from your realm provider,
                    // or configure them yourself for your self-hosted realm.
                    realms = arrayOf(Realm(
                        id = decoder.decode("AQIDBAUGBwgJCgsMDQ4PEA=="),
                        address = "https://some/realm/address1",
                        publicKey = decoder.decode("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
                    ),
                    Realm(
                        id = deocder.decode("EA8ODQwLCgkIBwYFBAMCAQ=="),
                        address = "https://some/realm/address2",
                        publicKey = decoder.decode("IB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE=")
                    )),
                    registerThreshold = 2,
                    recoverThreshold = 2,
                    pinHashingMode = PinHashingMode.STANDARD_2019
                ),
                authTokens = mapOf(
                  decoder.decode("AQIDBAUGBwgJCgsMDQ4PEA==") to authToken1,
                  deocder.decode("EA8ODQwLCgkIBwYFBAMCAQ==") to authToken2
                )
            )
```

Once you've created a client, you can register a secret for the `authToken`'s user by calling:

```kotlin
client.register("1234".toByteArray(), "secret".toByteArray(), 5)
```

To recover the secret you just registered, you can call:

```kotlin
val secret = String(client.recover("1234".toByteArray()))
```

And when you're ready to delete any secret from the remote store, simply call:

```kotlin
client.delete()
```
