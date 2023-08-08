## Juicebox SDK

An interface for the Juicebox Protocol which provides distributed storage and recovery of secrets using simple PIN authentication.

This interface is implemented in [Rust](rust/sdk/README.md), but is also bridged to support [Swift](swift/README.md), [Android](android/README.md), and [JavaScript](javascript/README.md).

For a more in-depth explanation of the protocol – including the motivations behind it – read the [whitepaper](https://docs:JU1C380X@docs.juicebox.xyz/whitepapers/juiceboxprotocol_revision7_20230807.pdf).

### Authentication

The protocol requires authentication, using JSON Web Tokens, the creation of which is delegated away from the operators of the servers that store secrets. Sample Rust code for creating and validating these tokens can be found in the [tokens](rust/cli/tokens/README.md) CLI tool. Details on Authentication can be found in Section 4.5 of the Whitepaper.

The following sample code represents how a token could be created on a nodejs server:

```js
const jwt = require('jsonwebtoken');

// The signing key data will be provided by your realm operator
const signingKey = Buffer.from('a08ea78782b961462534032b2b2388ef5c59151e620d1ec7375fcf19b30241f1', "hex")

// The keyid (also known as "kid") will be provided along with the signing key
const header = { algorithm: 'HS256', keyid: 'acme:1' };

const payload = {
    iss: 'acme',                               // Tenant name – should match the `kid` field prior to `:`
    sub: 'artemis', 						   // UserId that will be registering / recovering secrets
    aud: 'b81d501016728117fc2f56285d0d142d',   // RealmId the token is valid for, this should be provided by your realm operator
    exp: Math.floor(Date.now() / 1000) + 3600, // Expiration time (in seconds), the lifetime of a token must not exceed one day, `exp - nbf <= 86_400`
    nbf: Math.floor(Date.now() / 1000) 		   // Not valid before time (in seconds)
};

const token = jwt.sign(payload, signingKey, header);

console.log('Generated JWT:', token);
```

### Related Crates

In addition to the SDK, this repo provides the following crates that may be useful outside of the SDK:

* [juicebox_noise](rust/noise/README.md) – A limited implementation of the Noise protocol, restricted to support for `Noise_NK_25519_ChaChaPoly_BLAKE2s`
* [juicebox_oprf](rust/oprf/README.md) – A 2HashDH OPRF implementation with additional support for DLEQ Zero-Knowledge proofs
* [juicebox_secret_sharing](rust/secret_sharing/README.md) – A generic implementation of Shamir's Secret Sharing utilizing Lagrange Basis Polynomials
