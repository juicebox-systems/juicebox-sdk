## JavaScript

Register and recover PIN-protected secrets on behalf of a particular user.

### Install

```
npm install -s juicebox-sdk
```

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth tokens should be acquired out-of-band from a server you run and specific to each realm id. All of the realms must be set up to accept this server's tokens.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```typescript
import { Client, Configuration, Realm, PinHashingMode } from 'juicebox-sdk';

const client = new Client(
    // You should receive the realm parameters from your realm provider,
    // or configure them yourself for your self-hosted realm.
    new Configuration({
        realms: [
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
        register_threshold: 3,
        recover_threshold: 3,
        pin_hashing_mode: "Standard2019"
    }),
    []
);

// fetch or read the correct token for the `realmId`
window.JuiceboxGetAuthToken = async (realmId) => authTokens[realmId];
```

Once you've created a client, you can register a secret for the `authToken`'s user by calling:

```typescript
await client.register(encoder.encode("1234"), encoder.encode("secret"), encoder.encode("info"), 2);
```

To recover the secret you just registered, you can call:

```typescript
const secret = await client.recover(encoder.encode("1234"), encoder.encode("info"));
```

And when you're ready to delete any secret from the remote store, simply call:

```typescript
await client.delete();
```
