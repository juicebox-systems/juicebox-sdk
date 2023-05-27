## Android

Register and recover PIN-protected secrets on behalf of a particular user.

[Documentation](https://docs.juicebox.xyz/android/juicebox-sdk/xyz.juicebox.sdk/)

### Install

#### Gradle

```
repositories {
  google()
  mavenCentral()
}

dependencies {
  implementation 'com.github.juicebox-systems.juicebox-sdk:juicebox-sdk:0.0.1'
}
```

#### Maven

```
<dependency>
  <groupId>com.github.juicebox-systems.juicebox-sdk</groupId>
  <artifactId>juicebox-sdk</artifactId>
  <version>0.0.1</version>
</dependency>
```

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth tokens should be acquired out-of-band from a server you run and specific to each realm id. All of the realms must be set up to accept this server's tokens. You can either provide a map of tokens that are valid for the lifetime of the client or implement the `Client.fetchAuthTokenCallback` to dynamically fetch tokens as necessary.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```kotlin
import xyz.juicebox.sdk.*

val client = Client(
                Configuration.fromJson(
                    // You should receive the realm parameters from your realm provider,
                    // or configure them yourself for your self-hosted realm.
                    """
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
                authTokens = mapOf(
                  RealmId(string = "0102030405060708090a0b0c0d0e0f10") to authToken1,
                  RealmId(string = "2102030405060708090a0b0c0d0e0f10") to authToken2,
                  RealmId(string = "3102030405060708090a0b0c0d0e0f10") to authToken3
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
