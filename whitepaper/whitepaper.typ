#import "template.typ": whitepaper

#show: whitepaper.with(
  title: "Juicebox Protocol",
  subtitle: "Distributed Storage and Recovery of Secrets Using Simple PIN Authentication",
  authors: (
    (name: "Nora Trapp", affiliation: "Juicebox Systems, Inc"),
    (name: "Diego Ongaro", affiliation: "Juicebox Systems, Inc"),
  ),
  date: "June 7, 2023",
  version: "Revision 2",
  abstract: [Existing secret management techniques often demand users memorize complex passwords, store convoluted recovery phrases, or place their trust in a specific service or hardware provider. We present a novel protocol that combines existing cryptographic techniques to eliminate these complications and reduce user complexity to recalling a short PIN. Our protocol specifically focuses on a distributed approach to secret storage that leverages _Oblivious Pseudorandom Functions_ (OPRFs) and a _Secret-Sharing Scheme_ (SSS) combined with self-destructing secrets to minimize the trust placed in any singular server. Additionally, our approach allows for servers distributed across organizations, eliminating the need to trust a singular service operator. We have built a reference open-source implementation of the client and server sides of this new protocol, the latter of which has variants for running on commodity hardware and secure hardware.],
  bibliography-file: "references.bib",
)

= Introduction
Services are increasingly attempting to provide their users with strong, end-to-end encrypted privacy features, often with the direct goal of preventing the service operator from accessing user data. In such systems, the user is generally given the role of managing a secret key to decrypt and encrypt their data. Secret keys tend to be long, not memorable, and difficult for a user to reliably to reproduce, by design. The burden of this complexity becomes particularly apparent when the user must enter their key material on a new device.

Techniques like seed phrases @Palatinus_Rusnak_Voisine_Bowe_2013 provide some simplification to this process but still result in long and unmemorable strings of words that a user has to manage. Alternative approaches to key management such as passkeys @FIDO_Alliance_2019 reduce the user burden but ultimately require that a user still have access to a device containing the key material.

We present an approach — the _Juicebox Protocol_ — that allows the user to recover their secret material by remembering a short PIN, without having access to any previous devices.

Specifically, this protocol aims to:
+ Never give any service access to a user's secret material or PIN
+ Keep user burden low by allowing recovery through memorable low-entropy PINs while maintaining similar security to solutions utilizing high-entropy passwords
+ Distribute trust across mutually distrusting services, eliminating the need to trust any singular server operator or hardware vendor
+ Prevent brute-force attacks by self-destructing secrets after _n_ failed recoveries
+ Allow auditing of secret access attempts

Juicebox provides open-source reference implementations for both the client and server on GitHub @Juicebox_Github.

= Overview

== Configuration
A protocol client aims to distribute their secrets across _n_ mutually distrusting services that implement the _Juicebox Protocol_. For this paper, we will refer to each service that a secret can be distributed to as an abstract _Realm_, elaborated upon in @Realms.

The overall security of the protocol is directly related to the set of _n_ realms you configure your client with. Adding a _Realm_ to your configuration generally results in a net increase in security, although there can be some caveats.

When adding a _Realm_ to your configuration, some important questions to ask are:
- Who has access to the data stored on that _Realm_? (referred to as a _trust boundary_ going forward)
- Does that _trust boundary_ overlap with other realms in your configuration? If so, adding this _Realm_ may reduce your overall security.

Configurations of realms are often used in _threshold_ based operations. A $"threshold" < n$ allows increased availability of secrets when using a configuration with a larger size _n_ since not all realms are required to be operational or in agreement for the operation to succeed.

A $"threshold" >= 3$ is recommended where possible as small _n_ configurations have the weakest security promises.

We require a $"threshold" > n/2$ which ensures that a majority consensus can always be reached and independent disagreeing sets of realms $>="threshold"$ cannot exist in your configuration.

== Realms <Realms>
Fundamentally, each _Realm_ must adhere to the core protocol as defined here to be compatible. However, different realms may provide different security guarantees influencing the overall security of a user's secret value.

Each _Realm_ is assigned a unique 16-byte identifier known as a _Realm#sub[id]_. For implementation purposes, this could be any value as long as it is universally unique across realms in your configuration. We generally recommend using a random value.

A _Realm_ is controlled by an _operator_ — the organization or individual who runs the service. The level of trust that must be placed in a given operator varies based on the underlying realm implementation.

Communication with a _Realm_ should always occur over a secure protocol such as TLS that ensures the confidentiality and integrity of requests while limiting the possibility of replay attacks.

It should generally be assumed that each _Realm_ controls only a share of a user's secret value (via SSS, as described in @SSS) and that a singular realm never has access to the full secret material. This guarantee is best achieved by ensuring that realms spanning multiple _trust boundaries_ are utilized.

=== Hardware Realms
We explored a form of _Realm_ backed by secure hardware, such as a hardware security module (HSM), as an avenue for creating diversity in _trust boundaries_ within a client's configuration. Our primary focus with realms of this nature was on shifting the trust model away from the realm _operator_ and hosting provider and onto the hardware _vendor_.

For this purpose, we specifically focused on HSMs that are programmable with non-volatile memory, as encapsulating the protocol operations within the hardware's trusted execution environment (TEE) assures that a malicious operator has no avenue of access. Non-volatile memory is required to prevent an _operator_ from rolling back _Realm_ state, which could prevent self-destruction of secrets. The HSMs we explored also allow some authorized form of programming, such that an _operator_ can prove that a specific and verifiable version of the protocol is being executed within the TEE.

It must be noted that this shift in _trust boundaries_ does not come for free. HSMs come with significant tradeoffs in terms of acquisition and operation cost as well as performance when compared to commodity hardware. This makes an HSM product insufficient as a standalone secret storage solution at scale. However, when used in concert with other types of realms — including hardware realms from other vendors — we believe the inclusion of such realms can provide a significant increase in security.

=== Software Realms
We additionally explored a form of _Realm_ that can run on commodity hardware in common cloud providers. We specifically looked at this solution as the ease of deployment has the potential to significantly increase the number of _trust boundaries_ that exist within a configuration. This can be particularly convenient to augment costly hardware realms, reducing trust placed on any individual hardware vendor, and even allowing a single organization to operate multiple realms with different _trust boundaries_.

The software solutions we specifically explored by design do not attempt to limit the user's need to trust the operator and additionally require placing some degree of trust in the hosting or database provider. Since these realms only control an encrypted share of a user's secret value, we believe this is an acceptable tradeoff for the increased accessibility it provides.

It is also important to recognize that given the limited number of distinct cloud providers currently operating, overuse of such realms can potentially put too much secret information in one party's control and jeopardize user secrets.

== Tenants
In general, this protocol assumes that any given _Realm_ allows the storage and recovery of secrets from users spanning multiple organizational boundaries. We refer to each of these organizational boundaries as a _tenant_, and the protocol as defined ensures that any individual tenant can only perform operations on user secrets within their organizational boundary.

We encourage this multi-tenanted approach for realms, as we believe it enables a network effect that will broaden the adoption of the protocol. For example, realm operator _Alice_'s users no longer must trust _Alice_ if _Alice_ additionally distributes their secrets to realm operator _Bob_'s realm. To facilitate this exchange, _Alice_ could allow _Bob_'s organization to distribute its user secrets to her realm.

This model can also potentially reduce the costs of running expensive hardware realms by distributing the costs of operation across multiple tenants.

= Cryptographic Primitives
As a prerequisite to defining the protocol, we must define several cryptographic primitives that the protocol relies upon. Each of these is abstractly described, as the fundamental details of their implementation may evolve. For specific algorithms that we recommend as of the writing of this paper, see @Cryptographic_Implementation.

== Oblivious Pseudorandom Functions (OPRFs)
An OPRF is a cryptographic primitive that enables a server to securely evaluate a function on a client's input while ensuring the server learns nothing about the client's input and the client learns nothing about the server's key beyond the output of the function.

For this paper, we will define an OPRF exchange with the following abstract functions:

/ $"OprfDeriveKey"("seed")$: Returns an OPRF _key_ derived from the provided _seed_. The key generated from a specific seed will always be the same.
/ $"OprfBlind"("input")$: Performs the blinding step for the _input_ value and returns the _blindedInput_ and _blindingFactor_. This _blindedInput_ is sent from the client to the server.
/ $"OprfBlindEvaluate"("key", "blindedInput")$: Performs the evaluation step for the _blindedInput_ and returns the _blindedResult_. This _blindedResult_ is sent from the server to the client.
/ $"OprfFinalize"("blindedResult", "blindingFactor", "input")$: Performs the finalization step to unblind the _blindedResult_ using the _blindingFactor_ and the _input_ and returns the _result_.
/ $"OprfEvaluate"("key", "input")$: Computes the unblinded _result_ directly bypassing the oblivious exchange.

== Secret-Sharing Scheme (SSS) <SSS>
A secret-sharing scheme is a cryptographic algorithm that allows a secret to be divided into multiple shares, which are then distributed among different participants. Only by collecting a minimum number of shares — typically determined by a _threshold_ specified during share creation — can the original secret be reconstructed. This approach provides a way to securely distribute and protect sensitive information by splitting it into multiple fragments that individually reveal nothing about the original secret.

For this paper, we will define the following abstract functions for creating and reconstructing shares:

/ $"CreateShares"(n, "threshold", "secret")$: Distributes _secret_ into _n_ _shares_
/ $"RecoverShares"("shares")$: Recovers _secret_ from _n_ _shares_ or returns an error if $n < "threshold"$

== Noise Protocol <Noise>
In some implementations of the _Juicebox Protocol_, such as when utilizing a _Hardware Realm_, it can be necessary to implement additional abstraction layers in communication between the user and the realm software such that client communication cannot securely terminate within the realm software. Often, this might look like a load balancer that services several realms and terminates a TLS connection. This introduces the possibility of an intermediary party intercepting requests before they reach the realm software.

To prevent this, the _Juicebox Protocol_ allows for a _Realm_ to optionally generate a 32-byte key pair and distribute the public key to its clients. The realm may then implement the NK-handshake pattern of the Noise Protocol @Perrin_2018. Utilizing this public key allows users to establish a secure session directly with the realm software and encrypt each request with a new ephemeral key, regardless of additional hops a request may take to arrive at the _Realm_.

== Additional Primitives
In addition to the previously established _OPRF_ and _SSS_ primitives, the following common primitives are necessary to define the protocol:

/ $"Encrypt"("encryptionKey", "plaintext", "nonce")$: Returns an authenticated encryption of _plaintext_ with _encryptionKey_. The encryption is performed with the given _nonce_.
/ $"Decrypt"("encryptionKey", "ciphertext", "nonce")$: Returns the authenticated decryption of _ciphertext_ with _encryptionKey_. The decryption is performed with the given _nonce_.
/ $"KDF"("data", "salt")$: Returns a fixed 64-byte value that is unique to the input _data_ and _salt_.
/ $"MAC"("key", "input")$: Returns a 32-byte tag by combining the _key_ with the provided _input_.
/ $"Random"(n)$: Returns _n_ random bytes. The _Random_ function should ensure the generation of random data with high entropy, suitable for cryptographic purposes.

= Protocol
The _Juicebox Protocol_ can be abstracted to three simple operations — _register_, _recover_, and _delete_.

The following sections contain Python code that demonstrates the work required for each operation. For this code, we assume that the protocol has been appropriately configured with _n_ mutually distrusting realms, each of which will be referred to as _Realm#sub[i]_.

== State
_Realm#sub[i]_ will store a record indexed by the combination of the registering user's identifier (UID#footnote[As defined in @Authentication]) and their _tenant_. This ensures that a given _tenant_ may only authorize operations for its users.

Clients do not require any persistent state to recover their secrets and should just rely on the user's _PIN_ input.

This record can exist in one of three states:

/ NotRegistered: The user has no existing registration with this _Realm_. This is the default state if a user has never communicated with the _Realm_.
/ Registered: The user has registered secret information with this _Realm_ and can still attempt to restore that registration.
/ NoGuesses: The user has registered secret information with this _Realm_, but can no longer attempt to restore that registration.

A user transitions into the _NoGuesses_ state when the number of _attemptedGuesses_ on their registration equals or exceeds their _allowedGuesses_, self-destructing the registered data.

In the _Registered_ state, the following additional information is stored corresponding to the registration:

/ version: a unique 16-byte value that identifies this registration across all _Realms_
/ allowedGuesses: the maximum number of guesses allowed before the registration is permanently deleted by the _Realm_
/ attemptedGuesses#sub[i]: starts at 0 and increases on recovery attempts, then reset to 0 on successful recoveries
/ saltShares#sub[i]: a share of the salt the client generated during registration and used to hash their _PIN_
/ oprfSeeds#sub[i]: a random OPRF seed the client generated during registration, unique to this realm and this registration
/ maskedUnlockKeyShares#sub[i]: a masked share of the unlock key
/ unlockTags#sub[i]: the tag the client provides to demonstrate knowledge of the PIN and release _encryptedSecretShares#sub[i]_
/ encryptedSecretShares#sub[i]: a share of the user's encrypted secret

== Registration
Registration is a two-phase operation that a new user takes to store a PIN-protected secret. A registration operation is also performed to change a user's PIN or register a new secret for an existing user.

A reference client might expose registration in the following form:

$ "register"("pin", "secret", "allowedGuesses", "threshold", "associatedData") $

/ pin: represents a low entropy value known to the user that will be used to recover their secret, such as a 4-digit pin #footnote[While the protocol aims to provide strong security guarantees for low entropy pins, using a high entropy value here will provide increased security.]
/ secret: represents the secret value a user wishes to persist
/ allowedGuesses: specifies the number of failed attempts a user can make to recover their secret before it is permanently deleted
/ threshold: represents the number of realms that shares must be recovered from for the _secret_ to be restored
/ associatedData: known user data that is factored into the random _salt_ used to stretch the user's _PIN_ #footnote[Using a known constant, like the UID, can prevent a malicious _Realm_ from returning a fixed _salt_ with a pre-computed password table.]

=== Phase 1
The purpose of Phase 1 is to verify that at least _y_ realms are available to store a new registration, where $y >= "threshold"$. Ensuring registration succeeds on more realms than your _threshold_ increases availability during recovery.

An empty _register1_ request is sent from the client to each _Realm#sub[i]_.

For realms that expose a _public key_ and implement _Noise_, it is recommended to combine this request with the handshake if there is no open connection, as it does not reveal any sensitive information.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

Provided a client has completed _Phase 1_ on _y_ realms, the client can proceed to Phase 2.

=== Phase 2
The purpose of Phase 2 is to update the registration state on each _Realm#sub[i]_ to reflect the new _PIN_ and _secret_.

The following demonstrates the work a client should perform to prepare a new registration:

```python
def PrepareRegister2(realms, pin, secret, associatedData):
  version = Random(16)

  salt = Random(16)
  saltShares = CreateShares(y, threshold, salt)

  stretchedPin = KDF(pin, salt + associatedData)
  accessKey = stretchedPin[:32]
  encryptionKey = stretchedPin[-32:]

  # A `nonce` of 0 can be safely used since `encryptionKey` changes with each registration
  encryptedSecret = Encrypt(secret, encryptionKey, 0)
  encryptedSecretShares = CreateShares(len(realms), threshold, encryptedSecret)

  oprfSeeds = [Random(32) for _ in realms]
  oprfResults = [OprfEvaluate(OprfDeriveKey(seed), accessKey) for seed in oprfSeeds]

  unlockKey = Random(32)
  unlockKeyShares = CreateShares(len(realms), threshold, unlockKey)

  maskedUnlockKeyShares = [x ^ y for x, y in zip(unlockKeyShares, oprfResults)]

  unlockTags = [MAC(unlockKey, realm.id) for realm in realms]

  return (
      version,
      saltShares,
      oprfSeeds,
      maskedUnlockKeyShares,
      unlockTags,
      encryptedSecretShares
  )
```

A _register2_ request is then sent from the client to each _Realm#sub[i]_ that contains the prepared:
- version
- allowedGuesses
- saltShares#sub[i]
- oprfSeeds#sub[i]
- maskedUnlockKeyShares#sub[i]
- unlockTags#sub[i]
- encryptedSecretShares#sub[i]

Upon receipt of a _register2_ request, _Realm#sub[i]_ creates or overwrites the user's registration state with the corresponding values from the request.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

== Recovery
Recovery is a three-phase operation that an existing user takes to restore a PIN-protected secret.

A reference client might expose recovery in the following form:

$ "secret", "error" = "recover"("pin", "threshold", "associatedData") $

/ pin: represents the same value used during _register_
/ threshold: represents the same value used during _register_
/ associatedData: represents the same value used during _register_
/ secret: the recovered secret as provided during registration, if and only if the correct _pin_ was provided
/ error: indicates an error in recovery, such as an invalid _pin_ or the _allowedGuesses_ having been exceeded

=== Phase 1
The purpose of Phase 1 is to recover the _version_ and _saltShares#sub[i]_ from each _Realm#sub[i]_ and determine a set of realms to restore from.

An empty _recover1_ request is sent from the client to each _Realm#sub[i]_.

For realms that expose a _public key_ and implement _Noise_, it is recommended to combine this request with the handshake if there is no open connection, as it does not reveal any sensitive information.

The following demonstrates the work a _Realm#sub[i]_ should perform to process the request:

```python
def Recovery1(state, request):
  if state.isRegistered:
    if state.attemptedGuesses >= state.allowedGuesses:
      state.transitionToNoGuesses()
      return Error(NoGuesses)

    return Ok(state.version, state.saltShare)
  elif state.isNoGuesses:
    return Error(NoGuesses):
  elif state.isNotRegistered:
    return Error(NotRegistered)
```

An _OK_ response from this phase should always be expected to return the following information from the user's registration:
- version
- saltShares#sub[i]

Once a client has completed Phase 1 on at least _threshold_ _Realm#sub[i]_ with a majority consensus on the returned _version_ and _salt_ it can proceed to Phase 2. Only the realms that exist within this majority should be considered for the remaining phases. Provided the initial _threshold_ during registration consisted of a majority of realms, this consensus should always be reached as long as the user is registered. If this consensus cannot be reached, the client should assume that the user is _NotRegistered_ on any realm.

=== Phase 2
The purpose of Phase 2 is to increment the _attemptedGuesses_ for the user and recover the _maskedUnlockKeyShares_ stored during registration along with the _OPRF_ result required to unmask them and reconstruct the _unlockKey_. An optimal client can abort Phase 2 as soon as _threshold_ _OK_ responses are recovered, as this should be sufficient to recover the _unlockKey_.

By design, a client cannot recover their secret or determine the validity of their PIN by performing Phase 2 alone. This ensures that each realm has an opportunity to learn if the client succeeded or failed in their recovery attempt in order to audit their attempt appropriately and self-destruct their secret data if necessary.

The following demonstrates the work a client should perform to prepare for Phase 2:

```python
def PrepareRecovery2(realms, pin, associatedData, version, salt):
  stretchedPin = KDF(pin, salt + associatedData)
  accessKey = stretchedPin[:32]
  encryptionKey = stretchedPin[-32:]

  blindedAccessKeys, blindingFactors = zip(*[OprfBlind(accessKey) for _ in realms])

  return (
    accessKey,
    encryptionKey,
    blindedAccessKeys,
    blindingFactors
  )
```

A _recover2_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- blindedAccessKeys#sub[i]

The following demonstrates the work a _Realm#sub[i]_ should perform to process the request:

```python
def Recovery2(state, request):
  if state.isRegistered:
    if state.attemptedGuesses >= state.allowedGuesses:
      state.transitionToNoGuesses()
      return Error(NoGuesses)
    if request.version != state.version:
      return Error(VersionMismatch)

    oprfKey = OprfDeriveKey(state.oprfSeed)
    blindedResult = OprfBlindEvaluate(oprfKey, request.blindedAccessKey)

    state.attemptedGuesses += 1

    return Ok(blindedResult, state.maskedUnlockKeyShare)
  elif state.isNoGuesses:
    return Error(NoGuesses):
  elif state.isNotRegistered:
    return Error(NotRegistered)
```

An _OK_ response from this phase should always be expected to return the following information:
- blindedResult
- maskedUnlockKeyShares#sub[i]

Provided at least _threshold_ _OK_ responses have been received from Phase 2, a client can safely proceed to Phase 3.

=== Phase 3
The purpose of Phase 3 is to recover the _encryptedSecretShares_ allowing decryption and reconstruction of the user's _secret_. Additionally, this phase tells each _Realm#sub[i]_ the result of the operation so it can be audited appropriately.

Upon success this phase resets the _attemptedGuesses_ on each _Realm#sub[i]_ to 0. For this reason, a client should complete this process on _all_ realms that Phase 2 was performed on, even if sufficient material has been received to recover the user's _secret_. Otherwise, secret material may prematurely self-destruct.

The following demonstrates the work a client should perform to prepare for Phase 3:

```python
def PrepareRecovery3(
  realms,
  accessKey,
  blindingFactors,
  blindedResults,
  maskedUnlockKeyShares
):
  oprfResults = []
  for blindedResult, blindingFactor in zip(blindedResults, blindingFactors):
    oprfResults.append(OprfFinalize(blindedResult, blindingFactor, accessKey))

  unlockKeyShares = [x ^ y for x, y in zip(maskedUnlockKeyShares, oprfResults)]
  unlockKey = RecoverShares(unlockKeyShares)
  unlockTags = [MAC(unlockKey, realm.id) for realm in realms]

  return unlockTags
```

A _recover3_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- unlockTags#sub[i]

The following demonstrates the work a _Realm#sub[i]_ should perform to process the request:

```python
def Recovery3(state, request):
  if state.isRegistered:
    if request.version != state.version:
      return Error(VersionMismatch)

    if !ConstantTimeCompare(request.unlockTag, state.unlockTag):
      guessesRemaining = state.allowedGuesses - state.attemptedGuesses

      if guessesRemaining == 0:
        state.transitionToNoGuesses()

      return Error(BadUnlockTag(guessesRemaining))

    state.attemptedGuesses = 0

    return Ok(state.encryptedSecretShare)
  elif state.isNoGuesses:
    return Error(NoGuesses):
  elif state.isNotRegistered:
    return Error(NotRegistered)
```

An _OK_ response from this phase should always be expected to return the following information from the user's registration state:
- encryptedSecretShares#sub[i]

A _BadUnlockTag_ response from this phase should always be expected to return the previously determined:
- guessesRemaining

Upon receipt of _threshold_ _OK_ responses, the client can reconstruct the user's _secret_.

The following demonstrates the work a client should perform to do so:

```python
def RecoverSecret(encryptionKey, encryptedSecretShares):
  encryptedSecret = RecoverShares(encryptedSecretShares)
  secret = Decrypt(encryptionKey, encryptedSecret, 0)
  return secret
```

== Deletion
Delete is a single-phase operation that reverts a user's registration state to _NotRegistered_.

A reference client might expose delete in the following form:
$ "delete"() $

It is important to note that _delete_ does not require the user's _pin_, since a user can always register a new secret effectively deleting any existing secrets.

=== Phase 1

An empty _delete_ request is sent from the client to each _Realm#sub[i]_.

Upon receipt of a _delete_ request _Realm#sub[i]_ sets the user's registration state to _NotRegistered_.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

== Authentication <Authentication>
To enforce _tenant_ boundaries and prevent unauthorized clients from self-destructing a user's secret, a given _Realm#sub[i]_ requires authentication proving that a user has permission to perform operations.

A _Realm#sub[i]_ aims to know as little as possible about users and consequently relies on individual tenants to determine whether or not a user is allowed to perform operations.

To delegate this control to tenants, a realm _operator_ must generate a random 32-byte signing key ($
"signingKey" = "Random"(32)$) for each _tenant_ they wish to access their _Realm#sub[i]_. This signing key should be provided an integer version _v_ and the tenant should be provided a consistent alphanumeric name _tenantName_ that is shared by both the realm _operator_ and the _tenant_.

Given this information, a _tenant_ must vend a signed JSON Web Token (JWT) @Jones_Bradley_Sakimura_2015 to grant a given user access to the realm.

The header of this JWT must contain a _kid_ field of _tenantName:v_ so that the _Realm#sub[i]_ knows which version _v_ of _tenantName_'s signing key to validate against.

The claims of this JWT must contain an _iss_ field equivalent to _tenantName_ and a _sub_ field that represents a persistent user identifier (UID) the realm can use for storing secrets. Additionally, an _aud_ field must be present and contain a single hex-string equivalent to the _Realm#sub[i(id)]_ a token is valid for.

A _Realm#sub[i]_ must reject any connections that:
+ Don't contain an authentication token
+ Aren't signed with a known signing key for a given _tenantName_ and version _v_ matching the _kid_
+ Don't have an _aud_ exactly matching their _Realm#sub[i(id)]_

The operations defined in the prior sections assume all requests contain valid authentication tokens for a given _Realm#sub[i]_ or that an _InvalidAuthentication_ (401) error is returned by the _Realm_.

= Implementation Considerations

== Post-Quantum and OPRFs
While we have not performed extensive exploration into the state of post-quantum OPRFs, we believe that using a PQ-confidential transport ensures that even if an attacker was able to record the OPRF outputs today, they would not be able to later utilize an _unlockTag_ gleaned from them in any meaningful way. The user's _secret_ is still protected within the Phase 3 response. This assumes that the protocol has sufficiently evolved by this point, or that the user has otherwise re-registered their secret rotating their _oprfSeed_, such that the _unlockTag_ could not be provided directly in new interaction with a _Realm_.

== Registration Generations
The current protocol assumes that each realm stores either 0 or 1 record per user. While this approach is simple, it does have a downside in the specific scenario of a user re-registering. If the re-registration succeeds locally but fails globally (it succeeds on some realms but not enough to reach a threshold), then the user may be unable to recover their secret using either the old or new PIN. They will need to try again later to register successfully.

This downside could be resolved by adding the concept of _generations_ to realms allowing users to store _n_ registrations on a realm. During recovery, a user could fall back to the latest generation that still has at least _threshold_ realms available to recover from, so a failed registration would not erase their existing registration.

= Recommended Cryptographic Algorithms <Cryptographic_Implementation>

== OPRFs
The protocol relies on multiple _OPRF_ functions to ensure a _Realm_ does not gain access to the user's PIN.

We recommend utilizing OPRFs as described in the working draft by Davidson _et al._ @Davidson_Faz-Hernandez_Sullivan_Wood_2023 with the _Ristretto255_ curve as defined by Valence _et al._ @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023. Note that other cipher suites could also be potentially suitable depending on hardware and software constraints. In particular, we recognize that certain HSMs may place restrictions on available cipher suites.

== SSS
The protocol relies on a secret-sharing scheme to ensure a _Realm_ does not gain access to the user's secret.

We recommend utilizing the scheme defined by Shamir @Shamir_1979, but other schemes are viable.

== KDF
The protocol relies on a _KDF_ function to add entropy to the user's _PIN_, which provides an additional layer of protection if a _threshold_ of realms were to be compromised. While the specific hashing algorithm is up to the client, we recommend utilizing _Argon2_ @Biryukov_Dinu_Khovratovich_2015.

Determining the appropriate configuration parameters for Argon2 is highly dependent on the limitations of your client hardware. Additionally, since users may register and recover secrets across multiple devices a given user is specifically limited by the weakest device they expect to use. An intelligent client could potentially adjust a user's hashing strength based on the performance of their registered devices, assuming user devices only get more performant. This is of course not a valid assumption in many common cases.

For the common case, we have evaluated performance across popular smartphones and browsers circa 2019 and determined the following recommended parameters: #footnote[Parts of this evaluation were performed in 2019 at the Signal Foundation as part of their Secure Value Recovery project.]
- Utilize Argon2id to defend against timing and GPU attacks
- Utilize parallelism of 1 (limited primarily by browser-based threading)
- Utilize 32 iterations
- Utilize 16 KiB of memory (limited primarily by low-end Android devices)

We believe this combination of parameters provides a reasonable balance between performance — a user will not wait minutes to register a secret — and security.

A client may always re-register utilizing new parameters to provide stronger guarantees in the future.

== Secret Encryption
The protocol relies on an authenticated _Encrypt_ and _Decrypt_ function to ensure that the user's PIN is required to access the secret value, even if secret shares are compromised. While the specific encryption algorithm is up to the client, we recommend utilizing _ChaCha20_ and _Poly1305_ @Nir_Langley_2015.

== Tag MAC
The protocol relies on a _MAC_ function to compute an _unlockTag_ for a given realm. While the specific algorithm is up to the client, we recommend utilizing _HMAC_ over _BLAKE2s-256_ @Saarinen_Aumasson_2015.

= Acknowledgements
- The protocol is heavily based on design and feedback from Trevor Perrin and Moxie Marlinspike.
- The protocol builds on concepts closely related to those explored by Jarecki _et al._ in their PPSS @Jarecki_Kiayias_Krawczyk_Xu_2016 primitive and Davies _et al._ in their _Perks_ @Davies_Pijnenburg_2022 design.
- Some of the ideas utilized in this design were first suggested by the Signal Foundation in the future-looking portion of their _"Secure Value Recovery"_ blog post @Lund_2019.

= References
