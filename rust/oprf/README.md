A robust OPRF based on 2HashDH and a Chaum-Pedersen DLEQ proof.

This can be used as a basic OPRF, as a robust OPRF that verifies server
behavior according to a trusted public key, or as building blocks towards a
robust threshold OPRF.

The OPRF and proof use Ristretto255 (Curve25519) and SHA-512 internally.

The OPRF is based on 2HashDH. See the JKK14 paper for a definition:

> Jarecki, S., Kiayias, A., and Krawczyk, H.: "Round-Optimal Password-Protected
> Secret Sharing and T-PAKE in the Password-Only Model. Cryptology ePrint
> Archive, Report 2014/650 (2014), <https://eprint.iacr.org/2014/650>.

Note that, unlike JKK14, this implementation does not include the public key in
the output hash.

The DLEQ proof is based on
<https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf> page 838,
which presents the Chaum-Pedersen protocol with a Fiat-Shamir transform and an
optimization for proof size. The same proof protocol appears on page 10 of the
full JKK14 paper with different variable names.

#### Related Work

The IRTF draft [Oblivious Pseudorandom Functions (OPRFs) using Prime-Order
Groups](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/) defines an
OPRF and VOPRF and has many implementations in different languages. The OPRF is
simlar to this one, as both are based on 2HashDH. The VOPRF proof is optimized
for batches, at the expense of single-evaluation performance. Generating a
batched proof requires a minimum of 4 scalar-point multiplications instead of
the 2 required by a Chaum-Pedersen proof. Note that, unlike JKK14's VOPRF
definition, the output hash in the IRTF draft VOPRF does not include the public
key.

# Examples

#### OPRF

This example shows a client interacting with a server to compute the result,
without verifying that the server's output is correct. Normally, the client
would not have access to the server's private key.

```rust
# let rng = &mut rand_core::OsRng;
use juicebox_oprf as oprf;
let private_key = oprf::PrivateKey::random(rng);
let input = b"secret";

// Client
let (blinding_factor, blinded_input) = oprf::start(input, rng);

// Server
let blinded_output = oprf::blind_evaluate(&private_key, &blinded_input);

// Client
let output = oprf::finalize(input, &blinding_factor, &blinded_output);
```

#### Robust OPRF

This example shows a client interacting with a server to compute the result,
and verifying that the server's output is correct. Normally, the client would
not have access to the server's private key. In this protocol, the client must
somehow trust the public key.

```rust
# let rng = &mut rand_core::OsRng;
use juicebox_oprf as oprf;
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

#### PRF

This example shows how to directly compute the output, without a client-server
protocol. The output is exactly the same as the OPRF's.

```rust
# let rng = &mut rand_core::OsRng;
use juicebox_oprf as oprf;
let private_key = oprf::PrivateKey::random(rng);
let input = b"secret";

let output = oprf::unoblivious_evaluate(&private_key, input);
```
