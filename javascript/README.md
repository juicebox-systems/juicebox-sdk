## JavaScript

Register and recover PIN-protected secrets on behalf of a particular user.

### Install

```
npm install -s loam-sdk
```

### Usage

Instantiate a `Client` with the appropriate `Realm`s you wish to communicate with.

The auth token should be acquired out-of-band from a server you run, and that has communicated to the configured `Realm`s who a valid user is.

For maximum security, we recommend utilizing multiple realms with a register and recover threshold greater than 1.

```typescript
import { Client, Configuration, Realm, PinHashingMode } from 'loam-sdk';

const client = new Client(
    new Configuration(
        // You should receive the realm parameters from your realm provider,
        // or configure them yourself for your self-hosted realm.
        [new Realm(
            "https://some/realm/address",
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )],
        1,
        1,
        PinHashingMode.Standard2019
    ),
    [],
    authToken
);
```

Once you've created a client, you can register a secret for the `authToken`'s user by calling:

```typescript
await client.register(encoder.encode("1234"), encoder.encode("secret"), 2);
```

To recover the secret you just registered, you can call:

```typescript
const secret = await client.recover(encoder.encode("1234"));
```

And when you're ready to delete all secrets from remote store, simply call:

```typescript
await client.delete_all();
```
