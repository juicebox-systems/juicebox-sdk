A simple and generic implementation of Shamir's Secret Sharing utilizing Lagrange Basis Polynomials to allow the creation of shares of a _secret_ value that can later be used to reconstruct the _secret_ as long as _threshold_ shares are provided.

A `Secret` trait is exposed that types can conform to in order to support secret sharing.

Support for using scalars and points of the Ristretto255 group as `Secret` values is built-in.

Additionally, this implementation supports combinatorial recovery of shares which can be used as a rudimentary method for combating adversarial shares, provided the user has some way to validate the final recovered _secret_ value.

# Usage

```rust
# let rng = &mut rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use juicebox_secret_sharing::{create_shares, recover_secret, recover_secret_combinatorially, Secret, Share};

let secret = Scalar::random(rng);
let threshold = 5;
let num_shares = 10;

// Create Shares
let scalar_shares: Vec<_> = create_shares(&secret, threshold, num_shares, rng).collect();

// Recover secret from threshold subset
let recovered_secret = recover_secret(&scalar_shares[0..threshold as usize]).unwrap();

assert_eq!(secret, recovered_secret);

// Recover value indistinguishable from random from a less than threshold subset
let random_secret = recover_secret(&scalar_shares[0..(threshold as usize - 1)]).unwrap();

assert_ne!(secret, random_secret);

// Replace shares with random values, leaving only one valid threshold combination
let malicious_scalar_shares: Vec<_> = scalar_shares
    .into_iter()
    .enumerate()
    .map(|(i, s)| {
        if i < (num_shares - threshold) as usize {
            return Share {
                index: s.index,
                secret: Scalar::random(rng),
            };
        }
        s
    })
    .collect();

// Combinatorial recovery
let recover_combinatorial_secret = recover_secret_combinatorially(&malicious_scalar_shares, threshold, |potential_secret| {
    // In practice, this validation should be against a public MAC or Hash of the secret value
    if potential_secret == secret {
        Some(potential_secret)
    } else {
        None
    }
}).unwrap();

assert_eq!(secret, recover_combinatorial_secret);
```
