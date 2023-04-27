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

The auth token should be acquired out-of-band from a server you run, and that has communicated to the configured `Realm`s who a valid user is.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```kotlin
import me.loam.sdk.*

val client = Client(
                Configuration(
                    // You should receive the realm parameters from your realm provider,
                    // or configure them yourself for your self-hosted realm.
                    realms = arrayOf(Realm(
                        id = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u).toByteArray(),
                        address = "https://some/realm/address",
                        publicKey = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u, 19u, 20u, 21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 32u).toByteArray()
                    )),
                    registerThreshold = 1,
                    recoverThreshold = 1,
                    pinHashingMode = PinHashingMode.STANDARD_2019
                ),
                authToken = authToken
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

And when you're ready to delete all secrets from remote store, simply call:

```kotlin
client.deleteAll()
```
