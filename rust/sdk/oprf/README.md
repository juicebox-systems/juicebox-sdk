An OPRF and VOPRF based on 2HashDH and a Chaum-Pedersen DLEQ proof.

See the JKK14 paper for 2HashDH:

> Jarecki, S., Kiayias, A., and H. Krawczyk, "Round-Optimal Password-Protected
> Secret Sharing and T-PAKE in the Password-Only Model", Lecture Notes in
> Computer Science pp. 233-253, DOI 10.1007/978-3-662-45608-8_13, 2014,
> <https://doi.org/10.1007/978-3-662-45608-8_13>.

#### Related Work

The IRTF draft [Oblivious Pseudorandom Functions (OPRFs) using Prime-Order
Groups](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/) defines an
OPRF and VOPRF and has many implementations in different languages. The OPRF is
simlar to this one, as both are based on 2HashDH. The VOPRF proof is optimized
for batches, at the expense of single-evaluation performance. Generating a
batched proof requires a minimum of 4 scalar-point multiplications instead of
the 2 required by a Chaum-Pedersen proof.

# Examples

#### VOPRF

This example shows a client interacting with a server to compute the result,
and verifying that the server's output is correct. Normally, the client would
not have access to the server's private key. The client must somehow trust the
public key.

```rust
# let rng = &mut rand_core::OsRng;
use juicebox_sdk_oprf as oprf;
let private_key = oprf::PrivateKey::random(rng);
let public_key = private_key.to_public_key();
let input = b"secret";

// Client
let (blinding_factor, blinded_input) = oprf::start(input, rng);

// Server
let (blinded_output, proof) =
    oprf::blind_verifiable_evaluate(&private_key, &public_key, &blinded_input, rng);

// Client
oprf::verify_proof(&blinded_input, &blinded_output, &public_key, &proof).unwrap();
let output = oprf::finalize(input, &blinding_factor, &blinded_output);
```

#### OPRF

This example shows a client interacting with a server to compute the result,
without verifying that the server's output is correct. The OPRF output is
exactly the same as the VOPRF output. Normally, the client would not have
access to the server's private key.

```rust
# let rng = &mut rand_core::OsRng;
use juicebox_sdk_oprf as oprf;
let private_key = oprf::PrivateKey::random(rng);
let input = b"secret";

// Client
let (blinding_factor, blinded_input) = oprf::start(input, rng);

// Server
let blinded_output = oprf::blind_evaluate(&private_key, &blinded_input);

// Client
let output = oprf::finalize(input, &blinding_factor, &blinded_output);
```

#### PRF

This example shows how to directly compute the output, without a client-server
protocol. The output is exactly the same as in the VOPRF and OPRF.

```rust
# let rng = &mut rand_core::OsRng;
use juicebox_sdk_oprf as oprf;
let private_key = oprf::PrivateKey::random(rng);
let input = b"secret";

let output = oprf::unoblivious_evaluate(&private_key, input);
```
