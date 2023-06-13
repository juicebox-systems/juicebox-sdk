#import "template.typ": whitepaper

#show: whitepaper.with(
  title: "Juicebox Protocol",
  subtitle: "Distributed Storage and Recovery of Secrets Using Simple PIN Authentication",
  authors: (
    (name: "Nora Trapp", affiliation: "Juicebox Systems, Inc"),
    (name: "Diego Ongaro", affiliation: "Juicebox Systems, Inc"),
  ),
  date: "June 13, 2023",
  version: "Revision 4",
  abstract: [Existing secret management techniques demand users memorize complex passwords, store convoluted recovery phrases, or place their trust in a specific service or hardware provider. We have designed a novel protocol that combines existing cryptographic techniques to eliminate these complications and reduce user complexity to recalling a short PIN. Our protocol specifically focuses on a distributed approach to secret storage that leverages _Oblivious Pseudorandom Functions_ (OPRFs) and a _Secret-Sharing Scheme_ (SSS) combined with self-destructing secrets to minimize the trust placed in any singular server. Additionally, our approach allows for servers distributed across organizations, eliminating the need to trust a singular service operator. We have built an open-source implementation of the client and server sides of this new protocol, the latter of which has variants for running on commodity hardware and secure hardware.],
  bibliography-file: "references.bib",
)

= Introduction
Services are increasingly attempting to provide their users with strong, end-to-end encrypted privacy features, with the direct goal of preventing the service operator from accessing user data. In such systems, the user is generally given the role of managing a secret key to decrypt and encrypt their data. Secret keys tend to be long, not memorable, and difficult for a user to reliably reproduce, by design. The burden of this complexity becomes particularly apparent when the user must enter their key material on a new device.

Techniques like seed phrases @Palatinus_Rusnak_Voisine_Bowe_2013 provide some simplification to this process but still result in long and unmemorable strings of words that a user has to manage. Alternative approaches to key management such as passkeys @FIDO_Alliance_2019 reduce the user burden but ultimately require that a user still have access to a device containing the key material or otherwise backup their key material with a third party they trust.

We have designed the _Juicebox Protocol_ to solve these problems. It allows the user to recover their secret material by remembering a short PIN, without having access to any previous devices or placing their trust in any single party.

Specifically, this protocol:
+ Keeps user burden low by allowing recovery through memorable low-entropy PINs while maintaining similar security to solutions utilizing high-entropy passwords.
+ Never gives any service access to a user's secret material or PIN.
+ Distributes trust across mutually distrusting services, eliminating the need to trust any singular server operator or hardware vendor.
+ Prevents brute-force attacks by self-destructing secrets after a fixed number of failed recoveries.
+ Allows auditing of secret access attempts.

Juicebox provides open-source implementations for both the client and server on GitHub @Juicebox_Github.

= Overview
#figure(
  image("juicebox-diagram.png"),
  caption: [A configuration for a fictional tenant "Acme" demonstrating various realm types, operators, and their trust boundaries.],
) <Figure_1>

== Configuration
A protocol client distributes their secrets across _n_ mutually distrusting services that implement the _Juicebox Protocol_. For this paper, we will refer to each service that a secret can be distributed to as an abstract _Realm_, elaborated upon in @Realms.

The overall security of the protocol is directly related to the set of _n_ realms you configure your client with. Adding a _Realm_ to your configuration generally results in a net increase in security.

When adding a _Realm_ to your configuration, some important questions to ask are:
- Who has access to the data stored on that _Realm_? (referred to as a _trust boundary_ going forward)
- Does that _trust boundary_ overlap with other realms in your configuration? If so, adding this _Realm_ may reduce your overall security.

Configurations of realms are used in _threshold_ based operations. A _threshold_ is a definition of how many realms must participate for a secret to be recovered. Configuring a $"threshold" < n$ allows increased availability of secrets when using a configuration with a larger size since not all realms are required to be operational or in agreement for the operation to succeed.

== Realms <Realms>
A _Realm_ is a service capable of storing a distributed share of a user's secret. The following sections describe the two types of realms that we have implemented and the _trust boundaries_ associated with each type.

A _Realm_ is defined by the following information:

/ id: \ A 16-byte identifier uniquely representing this realm across all configured realms.
/ address: \ The fully qualified network address for connecting to the service.
/ publicKey: \ An optional 32-byte public key used to establish secure communications for hardware realms, where the realm controls a matching private key. See @Realm_Communication for more details.

=== Hardware Realms
This is a type of realm backed by secure hardware — specifically a hardware security module (HSM). Hardware realms provide tight _trust boundaries_ as only the HSM and the code it executes must be trusted. This difference is visible in @Figure_1.

=== Software Realms
This is a type of realm that runs on commodity hardware in common cloud providers. When paired with hardware realms, they are a valuable low-cost tool for increasing the number of _trust boundaries_ within a configuration.

== Tenants
Each _Realm_ allows the storage and recovery of secrets from users spanning multiple organizational boundaries. We refer to each of these organizational boundaries as a _tenant_, and the protocol as defined ensures that any individual tenant can only perform operations on user secrets within their organizational boundary. We utilize this multi-tenanted approach for realms as it reduces the costs of running realms by dividing the costs of operation across multiple tenants.

We also believe this model enables a network effect that will broaden the adoption of the protocol. For example, realm operator _A_'s users no longer must trust _A_ alone if _A_ additionally distributes their secrets to realm operator _B_'s realm. To facilitate this exchange, _A_ could allow _B_'s organization to distribute its user secrets to their realm.

= Cryptographic Primitives
As a prerequisite to defining the protocol, we must define several cryptographic primitives that the protocol relies upon. Each of these is abstractly described, as the fundamental details of their implementation may evolve. For specific algorithms that we recommend as of the writing of this paper, see @Cryptographic_Implementation.

== Oblivious Pseudorandom Functions (OPRFs)
An OPRF is a cryptographic primitive that enables a server to securely evaluate a function on a client's input while ensuring the server learns nothing about the client's input and the client learns nothing about the server's key beyond the output of the function.

For this paper, we will define an OPRF exchange with the following abstract functions:

/ $"OprfDeriveKey"("seed")$: \ Returns an OPRF _key_ derived from the provided _seed_. The key generated from a specific seed will always be the same.
/ $"OprfBlind"("input")$: \ Performs the blinding step for the _input_ value and returns the _blindedInput_ and _blindingFactor_. This _blindedInput_ is sent from the client to the server.
/ $"OprfBlindEvaluate"("key", "blindedInput")$: \ Performs the evaluation step for the _blindedInput_ and returns the _blindedResult_. This _blindedResult_ is sent from the server to the client.
/ $"OprfFinalize"("blindedResult", "blindingFactor", "input")$: \ Performs the finalization step to unblind the _blindedResult_ using the _blindingFactor_ and the _input_ and returns the _result_.
/ $"OprfEvaluate"("key", "input")$: \ Computes the unblinded _result_ directly bypassing the oblivious exchange.

== Secret-Sharing Scheme (SSS) <SSS>
A secret-sharing scheme is a cryptographic algorithm that allows a secret to be divided into multiple shares, which are then distributed among different participants. Only by collecting a minimum number of shares — typically determined by a _threshold_ specified during share creation — can the original secret be reconstructed. This approach provides a way to securely distribute and protect sensitive information by splitting it into multiple fragments that individually reveal nothing about the original secret.

For this paper, we will define the following abstract functions for creating and reconstructing shares:

/ $"CreateShares"(n, "threshold", "secret")$: \ Distributes _secret_ into _n_ _shares_ that can be recovered when _threshold_ are provided.
/ $"RecoverShares"("shares")$: \ Recovers _secret_ from _n_ _shares_ or returns an error if $n < "threshold"$.

== Additional Primitives
In addition to the previously established _OPRF_ and _SSS_ primitives, the following common primitives are necessary to define the protocol:

/ $"Encrypt"("encryptionKey", "plaintext", "nonce")$: \ Returns an authenticated encryption of _plaintext_ with _encryptionKey_. The encryption is performed with the given _nonce_.
/ $"Decrypt"("encryptionKey", "ciphertext", "nonce")$: \ Returns the authenticated decryption of _ciphertext_ with _encryptionKey_. The decryption is performed with the given _nonce_.
/ $"KDF"("data", "salt")$: \ Returns a fixed 64-byte value that is unique to the input _data_ and _salt_.
/ $"MAC"("key", "input")$: \ Returns a 32-byte tag by combining the _key_ with the provided _input_.
/ $"Random"(n)$: \ Returns _n_ random bytes. The _Random_ function should ensure the generation of random data with high entropy, suitable for cryptographic purposes.

= Protocol
The _Juicebox Protocol_ can be abstracted to three simple operations — _register_, _recover_, and _delete_.

The following sections contain Python code that demonstrates the work performed by each operation.

For this code, we assume that the protocol client has been appropriately configured with:
- _n_ mutually distrusting realms, each of which will be referred to as _Realm#sub[i]_
- $"threshold <= n"$ indicating how many realms must be available for recovery to succeed

== Realm#sub[i] State
_Realm#sub[i]_ will store a record indexed by the combination of the registering user's identifier (UID, as defined in @Authentication) and their _tenant_. This ensures that a given _tenant_ may only authorize operations for its users.

This record can exist in one of three states:

/ NotRegistered: \ The user has no existing registration with this _Realm_. This is the default state if a user has never communicated with the _Realm_.
/ Registered: \ The user has registered secret information with this _Realm_ and can still attempt to restore that registration.
/ NoGuesses: \ The user has registered secret information with this _Realm_, but can no longer attempt to restore that registration.

A user transitions into the _NoGuesses_ state when the number of _attemptedGuesses_ on their registration equals or exceeds their _allowedGuesses_, self-destructing the registered data.

In the _Registered_ state, the following additional information is stored corresponding to the registration:

/ version: \ A 16-byte value that uniquely identifies this registration for this UID across all configured _Realms_.
/ allowedGuesses: \ The maximum number of guesses allowed before the registration is permanently deleted by the _Realm#sub[i]_.
/ attemptedGuesses#sub[i]: \ The number of times recovery has been attempted on _Realm#sub[i]_ without success. Starts at 0 and increases on recovery attempts, then reset to 0 on successful recoveries.
/ saltShares#sub[i]: \ A single share of the salt the client generated during registration and used to hash their _PIN_.
/ oprfSeeds#sub[i]: \ A random OPRF seed the client generated during registration for this _Realm#sub[i]_.
/ maskedUnlockKeyShares#sub[i]: \ A single share of the unlock key masked by the OPRF result such that even if _threshold_ shares were recovered, the _unlockKey_ cannot be recovered without knowing the user's _PIN_.
/ unlockTags#sub[i]: \ A tag unique to this _Realm#sub[i]_ derived during registration from the _unlockKey_. The client will reconstruct this tag during recovery to prove knowledge of _PIN_ and be granted access to _encryptedSecretShares#sub[i]_.
/ encryptedSecretShares#sub[i]: \ A single share of the user's encrypted secret. Even if _threshold_ shares were recovered, the _secret_ cannot be decrypted without the user's _PIN_, _salt_, and _userInfo_.

== Registration
Registration is a two-phase operation that a new user takes to store a PIN-protected secret. A registration operation is also performed to change a user's PIN or register a new secret for an existing user.

The registration operations are exposed by the client in the following form:

$ "error" = "register"("pin", "secret", "allowedGuesses", "userInfo") $

/ pin: \ This argument contains a potentially low entropy value known to the user that will be used to recover their secret, such as a 4-digit PIN.
/ secret: \ This argument contains the secret value a user wishes to persist.
/ allowedGuesses: \ This argument specifies the number of failed attempts a user can make to recover their secret before it is permanently deleted.
/ userInfo: \ This argument contains user data that is factored into the random _salt_ used to stretch the user's _PIN_.
/ error: \ An error in registration, such as insufficient available realms.

=== Phase 1
The purpose of Phase 1 is to verify that at least _y_ realms are available to store a new registration, where $y >= "threshold"$. Ensuring registration succeeds on more realms than your _threshold_ increases availability during recovery.

An empty _register1_ request is sent from the client to each _Realm#sub[i]_.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

Once a client has completed _Phase 1_ on _y_ realms, it will proceed to Phase 2.

=== Phase 2
The purpose of Phase 2 is to update the registration state on each _Realm#sub[i]_ to reflect the new _PIN_ and _secret_.

The following demonstrates the work a client performs to prepare a new registration:

```python
  def PrepareRegister2(pin, secret, userInfo, realms, threshold):
    version = Random(16)

    salt = Random(16)
    saltShares = CreateShares(len(realms), threshold, salt)

    stretchedPin = KDF(pin, salt + userInfo)
    accessKey = stretchedPin[0:32]
    encryptionKey = stretchedPin[32:64]

    # A `nonce` of 0 can be safely used since `encryptionKey` changes with each registration
    encryptedSecret = Encrypt(secret, encryptionKey, 0)
    encryptedSecretShares = CreateShares(len(realms), threshold, encryptedSecret)

    oprfSeeds = [Random(32) for _ in realms]
    oprfResults = [OprfEvaluate(OprfDeriveKey(seed), accessKey) for seed in oprfSeeds]

    unlockKey = Random(32)
    unlockKeyShares = CreateShares(len(realms), threshold, unlockKey)

    maskedUnlockKeyShares = [XOR(x, y) for x, y in zip(unlockKeyShares, oprfResults)]

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

Upon receipt of a _register2_ request, _Realm#sub[i]_ creates or overwrites the user's registration state with the corresponding values from the request and resets the _attemptedGuesses_ to 0.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

== Recovery
Recovery is a three-phase operation that an existing user takes to restore a PIN-protected secret.

The recovery operations are exposed by the client in the following form:

$ "secret", "error" = "recover"("pin", "userInfo") $

/ pin: \ This argument represents the same value used during _register_.
/ userInfo: \ This argument represents the same value used during _register_.
/ secret: \ The recovered secret, as provided during registration, if and only if the correct _PIN_ was provided and no _error_ was returned.
/ error: \ An error in recovery, such as an invalid _PIN_ or the _allowedGuesses_ having been exceeded.

=== Phase 1
The purpose of Phase 1 is to recover the _version_ and _saltShares#sub[i]_ from each _Realm#sub[i]_ and determine a set of realms to restore from.

An empty _recover1_ request is sent from the client to each _Realm#sub[i]_.

The following demonstrates the work a _Realm#sub[i]_ performs to process the request:

```python
  def Recovery1(state, request):
    if state.isRegistered():
      if state.attemptedGuesses >= state.allowedGuesses:
        state.transitionToNoGuesses()
        return Error.NoGuesses()

      return Ok(state.version, state.saltShare)
    elif state.isNoGuesses():
      return Error.NoGuesses():
    elif state.isNotRegistered():
      return Error.NotRegistered()
```

An _OK_ response from this phase should always be expected to return the following information from the user's registration:
- version
- saltShares#sub[i]

Once a client has completed Phase 1 on at least _threshold_ _Realm#sub[i]_ that agree on _version_ and reconstructed the _salt_ from the _saltShares#sub[i]_, it will proceed to Phase 2 for those realms. If no realms are in agreement, the client will assume that the user is _NotRegistered_ on any realm.

=== Phase 2
The purpose of Phase 2 is to increment the _attemptedGuesses_ for the user and recover the _maskedUnlockKeyShares_ stored during registration along with the _OPRF_ result required to unmask them and reconstruct the _unlockKey_. The client finishes Phase 2 as soon as _threshold_ _OK_ responses are recovered, as this is sufficient material to recover the _unlockKey_.

By design, a client cannot recover the user's secret or determine the validity of the user's PIN by performing Phase 2 alone. This ensures that each realm has an opportunity to learn if the client succeeded or failed in their recovery attempt in order to audit their attempt appropriately and self-destruct their secret data if necessary.

The following demonstrates the work a client performs to prepare for Phase 2:

```python
  def PrepareRecovery2(pin, userInfo, realms, version, salt):
    stretchedPin = KDF(pin, salt + userInfo)
    accessKey = stretchedPin[0:32]
    encryptionKey = stretchedPin[32:64]

    blindOutputs = [OprfBlind(accessKey) for _ in realms]
    blindedAccessKeys = [k for k, _ in blindOutputs]
    blindingFactors = [f for _, f in blindOutputs]

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

The following demonstrates the work a _Realm#sub[i]_ performs to process the request:

```python
  def Recovery2(state, request):
    if state.isRegistered():
      if state.attemptedGuesses >= state.allowedGuesses:
        state.transitionToNoGuesses()
        return Error.NoGuesses()
      if request.version != state.version:
        return Error.VersionMismatch()

      oprfKey = OprfDeriveKey(state.oprfSeed)
      blindedResult = OprfBlindEvaluate(oprfKey, request.blindedAccessKey)

      state.attemptedGuesses += 1

      return Ok(blindedResult, state.maskedUnlockKeyShare)
    elif state.isNoGuesses():
      return Error.NoGuesses():
    elif state.isNotRegistered():
      return Error.NotRegistered()
```

An _OK_ response from this phase should always be expected to return the following information:
- blindedResult
- maskedUnlockKeyShares#sub[i]

Once at least _threshold_ _OK_ responses have been received from Phase 2, the client will safely proceed to Phase 3.

=== Phase 3
The purpose of Phase 3 is to recover the _encryptedSecretShares_ allowing decryption and reconstruction of the user's _secret_. Additionally, this phase tells each _Realm#sub[i]_ the result of the operation so it can be audited appropriately.

Upon success this phase resets the _attemptedGuesses_ on each _Realm#sub[i]_ to 0. For this reason, the client completes this process on _all_ realms that Phase 2 was performed on, even if sufficient material has been received to recover the user's _secret_. Otherwise, secret material may prematurely self-destruct.

The following demonstrates the work a client performs to prepare for Phase 3:

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

    unlockKeyShares = [XOR(x, y) for x, y in zip(maskedUnlockKeyShares, oprfResults)]
    unlockKey = RecoverShares(unlockKeyShares)
    unlockTags = [MAC(unlockKey, realm.id) for realm in realms]

    return unlockTags
```

A _recover3_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- unlockTags#sub[i]

The following demonstrates the work a _Realm#sub[i]_ performs to process the request:

```python
  def Recovery3(state, request):
    if state.isRegistered():
      if request.version != state.version:
        return Error.VersionMismatch()

      if !ConstantTimeCompare(request.unlockTag, state.unlockTag):
        guessesRemaining = state.allowedGuesses - state.attemptedGuesses

        if guessesRemaining == 0:
          state.transitionToNoGuesses()

        return Error.BadUnlockTag(guessesRemaining)

      state.attemptedGuesses = 0

      return Ok(state.encryptedSecretShare)
    elif state.isNoGuesses():
      return Error.NoGuesses():
    elif state.isNotRegistered():
      return Error.NotRegistered()
```

An _OK_ response from this phase should always be expected to return the following information from the user's registration state:
- encryptedSecretShares#sub[i]

A _BadUnlockTag_ response from this phase should always be expected to return the previously determined:
- guessesRemaining

Upon receipt of _threshold_ _OK_ responses, the client can reconstruct the user's _secret_.

The following demonstrates the work a client performs to do so:

```python
  def RecoverSecret(encryptionKey, encryptedSecretShares):
    encryptedSecret = RecoverShares(encryptedSecretShares)
    secret = Decrypt(encryptionKey, encryptedSecret, 0)
    return secret
```

== Deletion
Delete is a single-phase operation that reverts a user's registration state to _NotRegistered_.

The delete operation is exposed by the client in the following form:
$ "error" = "delete"() $

/ error: \ An error in delete, such as a transient network error.

This operation does not require the user's _PIN_ as a user can always register a new secret effectively deleting any existing secrets.

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
+ Don't contain an _iss_ matching the _tenantName_ in the _kid_

The operations defined in the prior sections assume all requests contain valid authentication tokens for a given _Realm#sub[i]_ or that an _InvalidAuthentication_ (401) error is returned by the _Realm_.

= Security Considerations
== Threshold Configuration
While any $"threshold" <= n$ is valid, we recommend a $"threshold" > n/2$ which ensures that there can be only at most one valid secret for a user at a time, avoiding uncertainty during Phase 1 of recovery.

Additionally, a $"threshold > 1"$ (and consequently $n > 1$) should always be used, as the security guarantees this protocol provides only apply when secrets are distributed across multiple realms.

== Hardware Realms
We specifically utilize HSMs that are programmable with non-volatile memory. Encapsulating the protocol operations within the hardware's trusted execution environment (TEE) assures that a malicious operator has no avenue of access. Non-volatile memory is required to prevent an operator from rolling back _Realm_ state, which could prevent the self-destruction of secrets. The HSMs we use also allow some authorized form of programming, such that an operator can prove that a specific and verifiable version of the protocol is being executed within the TEE.

Hardware realms assume that a combination of relatively opaque hardware and firmware is secure, which — outside of the _Juicebox Protocol_ — makes them not ideal as a standalone secret storage solution. However, when used in configuration with other types of realms — including hardware realms from other vendors — these risks can be mitigated.

== Software Realms
Since these realms only control an encrypted share of a user's secret, we believe it is an acceptable tradeoff that they require extending the _trust boundary_ to include the realm's _operator_ and _hosting provider_. It is important to recognize that given the limited number of distinct _hosting providers_ currently operating, overuse of such realms can potentially put too much secret information in one party's control and jeopardize user secrets.

== Realm Communication <Realm_Communication>
Communication with a _Realm_ always occurs over a secure protocol that ensures the confidentiality and integrity of requests while limiting the possibility of replay attacks. Towards this end, all requests to a realm are made over TLS.

Hardware Realms terminate this TLS connection outside of their _trust boundary_. This allows a single load balancer to service multiple HSMs but necessitates an additional layer of secure communication between the client and the HSM. For this layer, we use the _Noise Protocol_ @Perrin_2018 with an NK-handshake pattern with the realm's _public key_.

== Low-Entropy PINs
While the protocol provides strong security guarantees for low entropy PINs, using a higher entropy PIN provides increased security.

== Salting
The _register_ and _recover_ operations accept a _userInfo_ argument that is mixed into the _salt_ before passing it to the _KDF_. Using a known constant, like the UID, for this value can prevent a malicious _Realm_ from returning a fixed _salt_ with a pre-computed password table.

= Recommended Cryptographic Algorithms <Cryptographic_Implementation>

== OPRFs
The protocol relies on multiple _OPRF_ functions to ensure a _Realm_ does not gain access to the user's PIN.

We specifically utilize OPRFs as described in the working draft by Davidson _et al._ @Davidson_Faz-Hernandez_Sullivan_Wood_2023 with the cipher suite _Ristretto255_ @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023 Group and SHA-512 @Hansen_Eastlake_2011 Hash. Other cipher suites could also be potentially suitable depending on hardware and software constraints. In particular, certain HSMs may place restrictions on available cipher suites.

== SSS
The protocol relies on a secret-sharing scheme to ensure a _Realm_ does not gain access to the user's secret. We utilize the scheme defined by Shamir @Shamir_1979.

== KDF
The protocol relies on a _KDF_ function to add entropy to the user's _PIN_. When an expensive _KDF_ is utilized, this provides an additional layer of protection for low entropy PINs if a _threshold_ of realms were to be compromised. For this reason, we utilize _Argon2_ @Biryukov_Dinu_Khovratovich_2015.

Determining the appropriate configuration parameters for Argon2 is highly dependent on the limitations of your client hardware. Additionally, since users may register and recover secrets across multiple devices a given user is specifically limited by the weakest device they expect to use. An intelligent client could potentially adjust a user's hashing strength based on the performance of their registered devices, assuming user devices only get more performant. This is of course not a valid assumption in many common cases.

For the common case, we have evaluated performance across popular smartphones and browsers circa 2019 and defined the following recommended parameters: #footnote[Parts of this evaluation were performed in 2019 at the Signal Foundation as part of their Secure Value Recovery project.]
- Utilize Argon2id to defend against timing and GPU attacks
- Utilize parallelism of 1 (limited primarily by browser-based threading)
- Utilize 32 iterations
- Utilize 16 KiB of memory (limited primarily by low-end Android devices)

We believe this combination of parameters provides a reasonable balance between performance — a user will not wait minutes to register a secret — and security.

A client may always re-register utilizing new parameters to provide stronger guarantees in the future.

== Secret Encryption
The protocol relies on an authenticated _Encrypt_ and _Decrypt_ function to ensure that the user's PIN is required to access the secret value, even if secret shares are compromised. We utilize _ChaCha20_ and _Poly1305_ @Nir_Langley_2015.

== Tag MAC
The protocol relies on a _MAC_ function to compute an _unlockTag_ for a given realm. We utilize _BLAKE2s-MAC-256_ @Saarinen_Aumasson_2015.

= Acknowledgments
- The protocol is heavily based on design and feedback from Trevor Perrin and Moxie Marlinspike.
- The protocol builds on concepts closely related to those explored by Jarecki _et al._ in their PPSS @Jarecki_Kiayias_Krawczyk_Xu_2016 primitive and Davies _et al._ in their _Perks_ @Davies_Pijnenburg_2022 design.
- Some of the ideas utilized in this design were first suggested by the Signal Foundation in the future-looking portion of their _"Secure Value Recovery"_ blog post @Lund_2019.

= References
