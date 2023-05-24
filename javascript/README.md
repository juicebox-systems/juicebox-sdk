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
    new Configuration(
        // You should receive the realm parameters from your realm provider,
        // or configure them yourself for your self-hosted realm.
        [
            new Realm(
                "https://some/realm/address1",
                Uint8Array.from('AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=', c => c.charCodeAt(0)),
                Uint8Array.from('AQIDBAUGBwgJCgsMDQ4PEA==', c => c.charCodeAt(0)),
            ),
            new Realm(
                "https://some/realm/address2",
                Uint8Array.from('IB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE=', c => c.charCodeAt(0)),
                Uint8Array.from('EA8ODQwLCgkIBwYFBAMCAQ==', c => c.charCodeAt(0)),
            ),
        ],
        2,
        2,
        PinHashingMode.Standard2019
    ),
    []
);

// fetch or read the correct token for the `realmId`
window.JuiceboxGetAuthToken = async (realmId) => authTokens[realmId];
```

Once you've created a client, you can register a secret for the `authToken`'s user by calling:

```typescript
await client.register(encoder.encode("1234"), encoder.encode("secret"), 2);
```

To recover the secret you just registered, you can call:

```typescript
const secret = await client.recover(encoder.encode("1234"));
```

And when you're ready to delete any secret from the remote store, simply call:

```typescript
await client.delete();
```
