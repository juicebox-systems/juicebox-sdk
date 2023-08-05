#import "template.typ": whitepaper

#show: whitepaper.with(
  title: "Juicebox Protocol",
  subtitle: "Distributed Storage and Recovery of Secrets Using Simple PIN Authentication",
  authors: (
    (name: "Nora Trapp", affiliation: "Juicebox Systems, Inc"),
    (name: "Diego Ongaro", affiliation: "Juicebox Systems, Inc"),
  ),
  date: "August 4, 2023",
  version: "Revision 7",
  abstract: [Existing secret management techniques demand users memorize complex passwords, store convoluted recovery phrases, or place their trust in a specific service or hardware provider. We have designed a novel protocol that combines existing cryptographic techniques to eliminate these complications and reduce user complexity to recalling a short PIN. Our protocol specifically focuses on a distributed approach to secret storage that leverages _Oblivious Pseudorandom Functions_ (OPRFs) and a _Secret-Sharing Scheme_ (SSS) combined with self-destructing secrets to minimize the trust placed in any singular server. Additionally, our approach allows for servers distributed across organizations, eliminating the need to trust a singular service operator. We have built an open-source implementation of the client and server sides of this new protocol, the latter of which has variants for running on commodity hardware and secure hardware.],
  bibliography-file: "references.bib",
)

= Introduction
Services are increasingly attempting to provide their users with strong, end-to-end encrypted privacy features, with the direct goal of preventing the service operator from accessing user data. In such systems, the user is generally given the role of managing a secret key to decrypt and encrypt their data. Secret keys tend to be long, not memorable, and difficult for a user to reliably reproduce, by design. The burden of this complexity becomes particularly apparent when the user must enter their key material on a new device.

Techniques like seed phrases @Palatinus_Rusnak_Voisine_Bowe_2013 provide some simplification to this process but still result in long and unmemorable strings of words that a user has to manage. Alternative approaches to key management such as passkeys @FIDO_Alliance_2019 reduce the user burden but ultimately require that a user still have access to a device containing the key material or otherwise backup their key material with a third party they trust.

We have designed the _Juicebox Protocol_ to solve these problems. It allows the user to recover their secret material by remembering a short PIN, without having access to any previous devices or placing their trust in any single party.

Specifically, this protocol:
+ Keeps user burden low by allowing recovery through memorable low-entropy PINs, while maintaining similar security to solutions utilizing high-entropy passwords.
+ Never gives any service access to a user's secret material or PIN.
+ Distributes trust across mutually distrusting services, eliminating the need to trust any singular server operator or hardware vendor.
+ Prevents brute-force attacks by self-destructing secrets after a fixed number of failed recoveries.
+ Allows auditing of secret access attempts.

Juicebox provides open-source implementations for both the client and server on GitHub @Juicebox_Github.

= Overview
A protocol client distributes their secrets across _n_ mutually distrusting services that implement the _Juicebox Protocol_. For this paper, we will refer to each service that a secret can be distributed to as an abstract _Realm_, elaborated upon in @Realms.

The overall security of the protocol is directly related to the set of _n_ realms you configure your client with. Adding a _Realm_ to your configuration generally results in a net increase in security.

#figure(
  image("juicebox-diagram.png"),
  caption: [A configuration for a fictional tenant "Acme" demonstrating various realm types, operators, and their trust boundaries.],
) <Figure_1>

When adding a _Realm_ to your configuration, some important questions to ask are:
- Who has access to the data stored on that _Realm_? (referred to as a _trust boundary_ going forward)
- Does that _trust boundary_ overlap with other realms in your configuration? If so, adding this _Realm_ may reduce your overall security.

Configurations of realms are used in _threshold_-based operations. A _threshold_ is a definition of how many realms must participate for a secret to be recovered. Configuring a $"threshold" < n$ allows increased availability of secrets when using a configuration with a larger size since not all realms are required to be operational or in agreement for the operation to succeed.

== Realms <Realms>
A _Realm_ is a service capable of storing a distributed share of a user's secret. This section describe the two types of realms that we have implemented and the _trust boundaries_ associated with each type.

A _Realm_ is defined by the following information:

/ id: \ A 16-byte identifier uniquely representing this realm across all configured realms.
/ address: \ The fully qualified network address for connecting to the service.
/ publicKey: \ An optional 32-byte public key used to establish secure communications for hardware realms, where the realm controls a matching private key. See @Realm_Communication for more details.

A _hardware realm_ is a type of realm backed by secure hardware — specifically a hardware security module (HSM). Hardware realms provide tight _trust boundaries_ as only the HSM and the code it executes must be trusted. This difference is visible in @Figure_1.

A _software realm_ is a type of realm that runs on commodity hardware in common cloud providers. When paired with hardware realms, they are a valuable low-cost tool for increasing the number of _trust boundaries_ within a configuration.

== Tenants
Each _Realm_ allows the storage and recovery of secrets from users spanning multiple organizational boundaries. We refer to each of these organizational boundaries as a _tenant_, and the protocol as defined ensures that any individual tenant can only perform operations on user secrets within their organizational boundary. We utilize this multi-tenanted approach for realms as it reduces the costs of running realms by dividing the costs of operation across multiple tenants.

= Cryptographic Primitives
As a prerequisite to defining the protocol, we must define several cryptographic primitives that the protocol relies upon. Each of these is abstractly described, as the fundamental details of their implementation may evolve. For specific algorithms that we recommend as of the writing of this paper, see @Cryptographic_Implementation.

== Oblivious Pseudorandom Functions (OPRFs)
An OPRF is a cryptographic primitive that enables a server to securely evaluate a function on a client's input. This evaluation ensures the server learns nothing about the client's input and the client learns nothing about the server's key beyond the output of the function.

For this paper, we will define an OPRF exchange with the following abstract functions:

/ $"OprfBlind"("input")$: \ Performs the blinding step for the _input_ value and returns the _blindedInput_ and _blindingFactor_. This _blindedInput_ is sent from the client to the server.
/ $"OprfBlindEvaluate"("key", "blindedInput")$: \ Performs the evaluation step for the _blindedInput_ and returns the _blindedResult_. This _blindedResult_ is sent from the server to the client.
/ $"OprfFinalize"("blindedResult", "blindingFactor", "input")$: \ Performs the finalization step to unblind the _blindedResult_ using the _blindingFactor_ and the _input_ and returns the _result_.
/ $"OprfEvaluate"("key", "input")$: \ Computes the unblinded _result_ directly bypassing the oblivious exchange.

== Secret-Sharing Scheme (SSS) <SSS>
A secret-sharing scheme is a cryptographic primitive that allows a secret to be divided into multiple shares, which are then distributed among different participants. Only by collecting a minimum number of shares — typically determined by a _threshold_ specified during share creation — can the original secret be reconstructed. This approach provides a way to securely distribute and protect sensitive information by splitting it into multiple fragments that individually reveal nothing about the original secret.

For this paper, we will define the following abstract functions for creating and reconstructing shares:

/ $"CreateShares"(n, "threshold", "secret")$: \ Distributes a _secret_ into an ordered list of _n_ _shares_ that can be recovered when _threshold_ are provided.
/ $"RecoverShares"("indexedShares")$: \ Recovers a _secret_ from _y_ _indexedShares_ where each contains a corresponding _index_ from _1..N_ and _share_. If an invalid combination of shares is provided, an incorrect _secret_ will be returned that is indistinguishable from random.

== Threshold OPRFs (T-OPRFs)
A T-OPRF combines OPRFs and a secret-sharing scheme into a hybrid primitive that facilitates a highly-efficient oblivious exchange of an _input_ across a _threshold_ set of servers, allowing the computation of a single secret _result_ without revealing that _result_ to the servers. The correctness of the _result_ can be verified utilizing a _commitment_ computed during evaluation and finalization.

For this paper, we will define a T-OPRF exchange with the following abstract functions:

/ $"TOprfKeyShares"(n, "threshold", "rootKey")$: \ Returns _n_ shares of a _rootKey_ with the specified _threshold_. Each key share is sent to one server. This function is an alias of _CreateShares_.
/ $"TOprfBlind"("input")$: \ Performs the blinding step for the _input_ value and returns the _blindedInput_ and _blindingFactor_. This _blindedInput_ is sent from the client to each server. This function is an alias of _OprfBlind_.
/ $"TOprfBlindEvaluate"("keyShare", "blindedInput")$: \ Performs the evaluation step for the _blindedInput_ and returns the _blindedResult_. This _blindedResult_ is sent from each server to the client. This function is an alias of _OprfBlindEvaluate_.
/ $"TOprfFinalize"("blindedResults", "blindingFactor", "input")$: \ Performs the finalization step to unblind the set of _blindedResults_ returned from at least _threshold_ servers and returns a _result_ and a _commitment_ that can be used to validate that _result_ at a later point. If incorrect or insufficient shares of _blindedResults_ are present, the returned values will be indistinguishable from random. _TOprfFinalize_ can be implemented as _OprfFinalize(RecoverShares(blindedResults), blindingFactor, input)_ and splitting the _result_.
/ $"TOprfEvaluate"("rootKey", "input")$: \ Computes the unblinded _result_ and _commitment_ directly bypassing the oblivious exchange. The _commitment_ can be sent to the servers to validate the _result_ received from _TOprfFinalize_ at a later date. _TOprfEvaluate_ can be implemented as _OprfEvaluate(rootKey, input)_ and splitting the _result_.

== Robust T-OPRFs with Zero-Knowledge Proofs (ZKPs)
A ZKP is a cryptographic primitive that enables one party to demonstrate the truth of a statement to another party without revealing any additional information. Integrating ZKPs with T-OPRFs contributes to the protocol's robustness against misbehaving realms.

For this paper, we will define a ZKP with the following abstract functions:

/ $"TOprfProofGenerate"("privateKey", "publicKey", "blindedInput", "blindedOutput")$: \ Returns a _proof_ demonstrating that a server performed _TOprfBlindEvaluate_ with a trusted _privateKey_, without revealing the _privateKey_.
/ $"TOprfProofVerify"("proof", "publicKey", "blindedInput", "blindedOutput")$: \ Validates a _proof_ to confirm that a server generated the correct _blindedOutput_ from the _blindedInput_ using the _privateKey_ associated with a trusted _publicKey_.

== Digital Signature Algorithm (DSA)
A DSA is a cryptographic primitive that facilitates the generation and verification of digital signatures. These signatures rely on a key pair, comprised of a private signing key and a corresponding public verifying key. While the signing key is kept confidential and used for signing messages, the verifying key is openly shared to verify signatures.

For this paper, we will define a DSA with the following abstract functions:

/ $"NewSigningKey()"$: \ Returns a random private _signingKey_.
/ $"GenerateSignature"("signingKey", "message")$: \ Signs the given _message_ using the _signingKey_ and returns the a _signedMessage_ that contains the _signature_, _verifyingKey_, and original _message_.
/ $"VerifySignature"("signedMessage")$: \ Verifies the _signature_ was created with the private _signingKey_ associated with the public _verifyingKey_ for the specified _message_.

== Additional Primitives
In addition to the previously established _OPRF_, _SSS_, _T-OPRF_, and _ZKP_ primitives, the following common primitives are necessary to define the protocol:

/ $"Encrypt"("encryptionKey", "plaintext", "nonce")$: \ Returns an authenticated encryption of _plaintext_ with _encryptionKey_. The encryption is performed with the given _nonce_.
/ $"Decrypt"("encryptionKey", "ciphertext", "nonce")$: \ Returns the authenticated decryption of _ciphertext_ with _encryptionKey_. The decryption is performed with the given _nonce_.
/ $"KDF"("data", "salt", "info")$: \ Returns a fixed 64-byte value that is unique to the input _data_, _salt_, and _info_.
/ $"MAC"(n, "key", "*inputs")$: \ Returns an n-byte tag by combining the _key_ with the provided _inputs_. The _MAC_ function should encode the inputs unambiguously.
/ $"Random"(n)$: \ Returns _n_ random bytes. The _Random_ function should ensure the generation of random data with high entropy, suitable for cryptographic purposes.
/ $"Scalar"("seed")$: \ Returns a scalar created from a 64-byte seed value.
/ $"PublicKey"("scalar")$: \ Computes the _point_ representing the public key for a given _scalar_.

= Protocol
The _Juicebox Protocol_ can be abstracted to three simple operations — _register_, _recover_, and _delete_.

Utilizing the previously defined primitives, the protocol specifically aims to:

/ Prevent online brute-force attacks: \ Realms limit the number of unsuccessful recovery attempts to prevent online brute-force attacks against the user's _PIN_ (and OPRF key shares). Each realm independently increments an attempted guess count in phase 2 of recovery and disallows recoveries beyond the limit specified during registration. This counter is reset to zero in phase 3 of recovery if the client proves it knows the correct _PIN_.
/ Audit events: \ In phase 2 of recovery, a threshold of realms can log that a recovery is being attempted. For a successful recovery, a _threshold_ of realms can log during phase 3 that the client proved it knew the correct _PIN_ before the client could access their secret.
/ Store arbitrary secrets: \ The user stores a secret of their choosing, which provides flexibility to integrate with external systems. The user can also re-register with a new _PIN_, without changing the secret. To provide this flexibility, the recovered secret cannot be based on the T-OPRF _result_, which is pseudo-random and changes with every registration and _PIN_. Instead, the client stores the user's secret in an encrypted format during registration. In phase 3 of recovery, once the client proves it knows the correct _PIN_, it retrieves the encrypted secret, along with shares of a component of the encryption key.
/ Increase offline brute-force costs: \ As an additional layer of security, the client generates a unique salt per registration and combines this with the user's _PIN_ using a KDF. A portion of the KDF output is utilized as the T-OPRF input and as a seed for the key used to encrypt a user's secret. An adversary who has compromised a threshold of realms would need to additionally spend resources to brute-force each user's _PIN_ to access the secret. Using a resource-intensive KDF further increases the adversary's costs. The random salt also serves as the registration's version and is retrieved during phase 1 of recovery.
/ Exclude misbehaving realms: \ The protocol adds a layer of robustness to detect misbehaving realms and prevent them from interfering with recovery. This allows the client to proceed with recovery as long as a threshold number of correct realms are available, even if some realms are returning incorrect or adversarial results. It also allows the client to distinguish an incorrect PIN from incorrect realm behavior (otherwise, the T-OPRF _result_ appears incorrect for both cases). \ \ The protocol combines a few techniques to provide robustness:
#set list(indent: 3em)
- The client generates a signature of each realm's public OPRF key during registration, then discards the signing key (so that it cannot be used again). During phase 2 of recovery, the client identifies a _threshold_ of realms that agree on a verifying key with valid signatures for their public OPRF key corresponding to that verifying key.
- Each realm generates a ZKP in phase 2 of recovery. The proof allows the client to verify that the realm computed its share of the T-OPRF consistently with its OPRF key share.
- During registration, the client unobliviously evaluates the T-OPRF for the user's _PIN_ using the root OPRF key. A copy of the resulting public _commitment_ is stored with each realm. During phase 2 of recovery, the client identifies a threshold of realms that agree on a _commitment_ to recover from. It then verifies that the T-OPRF finalization produces a matching _commitment_. This prevents a colluding _threshold_ of realms from substituting different OPRF key shares and signatures without knowing the _PIN_.
- The client stores a secondary _commitment_ based on the T-OPRF _result_, the encrypted secret, and that realm's share of the encryption key with each realm during registration. During phase 3, the client verifies that the information about the user's secret returned from each realm is consistent with the _commitment_ stored during registration.

== Realm State
_Realm#sub[i]_ will store a record indexed by the combination of the registering user's identifier (UID, as defined in @Authentication) and their _tenant_'s name. This ensures that a given _tenant_ may only authorize operations for its users.

This record can exist in one of three states:

/ NotRegistered: \ The user has no existing registration with this _Realm_. This is the default state if a user has never communicated with the _Realm_.
/ Registered: \ The user has registered secret information with this _Realm_ and can still attempt to recover that registration.
/ NoGuesses: \ The user has registered secret information with this _Realm_, but can no longer attempt to recover that registration.

A user transitions into the _NoGuesses_ state when the number of _attemptedGuesses_ on their registration equals or exceeds their _allowedGuesses_, self-destructing the registered data.

In the _Registered_ state, the following additional information is stored corresponding to the registration:

/ version: \ A 16-byte value that uniquely identifies this registration for this user across all configured _Realms_. The version is random so that a malicious realm can't force a client to run out of versions. The version is also used as a salt that is combined with the user's PIN.
/ oprfPrivateKeys#sub[i]: \ A realm-specific OPRF private key derived by secret sharing a random root key.
/ unlockKeyCommitment: \ A 32-byte value derived during registration from the OPRF result used to verify the _unlockKey_.
/ oprfSignedPublicKey#sub[i]: \ A signed public key that corresponds to the _oprfPrivateKeys#sub[i]_ for this realm. Wraps the _publicKey_, a _signature_, and the public _verifyingKey_ for the _signingKey_ used to generate the _signature_.
/ unlockKeyTag#sub[i]: \ A tag unique to this _Realm#sub[i]_ derived during registration from the _unlockKey_. The client will reconstruct this tag during recovery to prove knowledge of the _PIN_ and be granted access to the secret.
/ encryptionKeyScalarShares#sub[i]: \ A single share of the random scalar used to derive the _encryptionKey_ for the user's secret. Even if _threshold_ shares were recovered, the _encryptionKey_ cannot be derived without knowing the user's _PIN_.
/ encryptedSecret: \ A copy of the user's encrypted secret.
/ encryptedSecretCommitment#sub[i]: \ A MAC derived from the _unlockKey_, _Realm#sub[id]_, encryptionKeyScalarShares#sub[i], and _encryptedSecret_. During recovery, the client can reconstruct this MAC to verify if _Realm#sub[i]_ has returned a valid share and secret.
/ allowedGuesses: \ The maximum number of guesses allowed before the registration is permanently deleted by the _Realm#sub[i]_.
/ attemptedGuesses#sub[i]: \ The number of times recovery has been attempted on _Realm#sub[i]_ without success. Starts at 0 and increases on recovery attempts, then reset to 0 on successful recoveries.

== Registration
Registration is a two-phase operation that a new user takes to store a PIN-protected secret. A registration operation is also performed to change a user's PIN or register a new secret for an existing user.

+ In phase 1, the client checks that at least _y_ realms are available to store the user's secret, where $y >= "threshold"$.
+ In phase 2, the client prepares and updates the registration _state_ on each Realm#sub[i].

The registration operations are exposed by the client in the following form:

$ "error" = "register"("pin", "secret", "allowedGuesses", "userInfo") $

/ pin: \ This argument contains a potentially low entropy value known to the user that will be used to recover their secret, such as a 4-digit PIN.
/ secret: \ This argument contains the secret value a user wishes to persist.
/ allowedGuesses: \ This argument specifies the number of failed attempts a user can make to recover their secret before it is permanently deleted.
/ userInfo: \ This argument contains per-user data that is combined with the random _salt_ used to stretch the user's _PIN_.
/ error: \ An error in registration, such as insufficient available realms.

The following sections contain Python code that demonstrates in detail the work performed by each phase.

For this code, we assume that the protocol client has been appropriately configured with:
- _n_ mutually distrusting realms, each of which will be referred to as _Realm#sub[i]_
- $"threshold" <= n$ indicating how many realms must be available for recovery to succeed

=== Phase 1 Registration
An empty _register1_ request is sent from the client to each _Realm#sub[i]_.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

Once a client has completed _Phase 1_ on _y_ realms, it will proceed to Phase 2.

=== Phase 2 Registration
The following demonstrates the work a client performs to prepare a new registration:

```python
  def PrepareRegister2(pin, secret, userInfo, realms, threshold):
    version = Random(16)

    stretchedPin = KDF(pin, version, userInfo)
    accessKey = stretchedPin[0:32]
    encryptionKeySeed = stretchedPin[32:64]

    oprfRootPrivateKey = Scalar(Random(64))
    oprfPrivateKeys = TOprfKeyShares(len(realms), threshold, oprfRootPrivateKey)

    unlockKeyCommitment, unlockKey = TOprfEvaluate(oprfRootPrivateKey, accessKey)

    signingKey = NewSigningKey()

    oprfSignedPublicKeys = [GenerateSignature(signingKey, PublicKey(key))
                            for key in oprfPrivateKeyShares]

    encryptionKeyScalar = Scalar(Random(64))
    encryptionKeyScalarShares = CreateShares(len(realms),
                                             threshold,
                                             encryptionKeyScalar)
    encryptionKey = MAC(32,
                        encryptionKeySeed,
                        "Encryption Key",
                        encryptionKeyScalar)

    # A `nonce` of 0 can be used since `encryptionKey` changes with each registration
    encryptedSecret = Encrypt(secret, encryptionKey, 0)

    encryptedSecretCommitments = [MAC(16,
                                      unlockKey,
                                      "Encrypted Secret Commitment",
                                      realm.id,
                                      share,
                                      encryptedSecret)
                                  for realm, share in zip(realms, encryptionKeyScalarShares)]

    unlockKeyTags = [MAC(16, unlockKey, "Unlock Key Tag", realm.id)
                     for realm in realms]

    return (
        version,
        oprfPrivateKeys,
        unlockKeyCommitment,
        oprfSignedPublicKeys,
        encryptionKeyScalarShares,
        encryptedSecret,
        encryptedSecretCommitments,
        unlockKeyTags
    )
```

A _register2_ request is then sent from the client to each _Realm#sub[i]_ that contains the prepared:
- version
- oprfPrivateKeys#sub[i]
- unlockKeyCommitment
- oprfSignedPublicKeys#sub[i]
- encryptionKeyScalarShares#sub[i]
- encryptedSecret
- encryptedSecretCommitments#sub[i]
- unlockKeyTags#sub[i]
- allowedGuesses

Upon receipt of a _register2_ request, _Realm#sub[i]_ creates or overwrites the user's registration state with the corresponding values from the request and resets the _attemptedGuesses_ to 0.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

The registration operation completes successfully with at least _y_ _OK_ responses.

== Recovery <Recovery>
Recovery is a three-phase operation that an existing user takes to recover a PIN-protected secret.

+ In phase 1, the client checks that a _threshold_ of realms with consensus on _version_ is available to recover the secret.
+ In phase 2, the client performs a T-OPRF exchange on the identified realms using an _input_ derived from the user's _PIN_.
+ In phase 3, the client uses the T-OPRF _result_ to derive tags for each realm that proves it knows the correct _PIN_. Then, each realm returns information that the client uses to reconstruct the user's secret.

The recovery operations are exposed by the client in the following form:

$ "secret", "error" = "recover"("pin", "userInfo") $

/ pin: \ This argument represents the same value used during _register_.
/ userInfo: \ This argument represents the same value used during _register_.
/ secret: \ The recovered secret, as provided during registration, if and only if the correct _PIN_ was provided and no _error_ was returned.
/ error: \ An error in recovery, such as an invalid _PIN_ or the _allowedGuesses_ having been exceeded.

The following sections contain Python code that demonstrates in detail the work performed by each phase.

For this code, we assume that the protocol client has been appropriately configured with:
- _n_ mutually distrusting realms, each of which will be referred to as _Realm#sub[i]_
- $"threshold" <= n$ indicating how many realms must be available for recovery to succeed

=== Phase 1 Recovery
An empty _recover1_ request is sent from the client to each _Realm#sub[i]_.

The following demonstrates the work a _Realm#sub[i]_ performs to process the request:

```python
  def Recovery1(state, request):
    if state.isRegistered():
      if state.attemptedGuesses >= state.allowedGuesses:
        state.transitionToNoGuesses()
        return Error.NoGuesses()

      return Ok(state.version)
    elif state.isNoGuesses():
      return Error.NoGuesses():
    elif state.isNotRegistered():
      return Error.NotRegistered()
```

An _OK_ response from this phase should always be expected to return the following information from the user's registration:
- version

Once a client has completed Phase 1 on at least _threshold_ _Realm#sub[i]_ that agree on _version_, it will proceed to Phase 2 for those realms. If no realms are in agreement, the client will assume that the user is _NotRegistered_ on any realm.

=== Phase 2 Recovery <Recovery_Phase_2>
The following demonstrates the work a client performs to prepare for Phase 2:

```python
  def PrepareRecovery2(pin, userInfo, realms, version, salt):
    stretchedPin = KDF(pin, salt, userInfo)
    accessKey = stretchedPin[0:32]
    encryptionKeySeed = stretchedPin[32:64]

    blindedAccessKey, blindingFactor = TOprfBlind(accessKey)

    return (
      accessKey,
      encryptionKeySeed,
      blindedAccessKey,
      blindingFactor
    )
```

A _recover2_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- blindedAccessKey

The following demonstrates the work a _Realm#sub[i]_ performs to process the request:

```python
  def Recovery2(state, request):
    if state.isRegistered():
      if state.attemptedGuesses >= state.allowedGuesses:
        state.transitionToNoGuesses()
        return Error.NoGuesses()
      if request.version != state.version:
        return Error.VersionMismatch()

      blindedResult = TOprfBlindEvaluate(state.oprfPrivateKey, request.blindedAccessKey)
      blindedResultProof = TOprfProofGenerate(state.oprfPrivateKey,
                            state.oprfPublicKey,
                            request.blindedAccessKey,
                            blindedResult
                          )

      state.attemptedGuesses += 1

      return Ok(blindedResult,
                blindedResultProof,
                state.oprfSignedPublicKey,
                state.unlockKeyCommitment,
                state.allowedGuesses,
                state.attemptedGuesses)
    elif state.isNoGuesses():
      return Error.NoGuesses():
    elif state.isNotRegistered():
      return Error.NotRegistered()
```

An _OK_ response from this phase should always be expected to return the following information:
- blindedResult
- blindedResultProof
- oprfSignedPublicKeys#sub[i]
- unlockKeyCommitment
- allowedGuesses
- attemptedGuesses

This phase will proceed until a client has completed it on at least _threshold_ _Realm#sub[i]_ that:
+ agree on an _unlockKeyCommitment_ and _verifyingKey_ for the _oprfSignedPublicKeys_
+ each have a valid _oprfSignedPublicKeys#sub[i]_:
  #v(-0.5em)
  ```python
    VerifySignature(oprfSignedPublicKey)
  ```
+ each have a valid _blindedResultProof_ for the _blindedResult_:
  #v(-0.5em)
  ```python
    TOprfProofVerify(
      blindedResultProof,
      oprfSignedPublicKey.publicKey,
      blindedAccessKey,
      blindedResult
    )
  ```

If this cannot be completed on _threshold_ realms, the client must assume a fault on the realms and may need to re-register or try again later.

If completed successfully, the client will attempt to recover the _unlockKey_.

The following demonstrates the work the client performs to reconstruct and validate the _unlockKey_:

```python
  def RecoverUnlockKey(
    blindingFactor,
    accessKey,
    unlockKeyCommitment,
    blindedResults,
    allowedGuesses,
    attemptedGuesses
  ):
    ourUnlockKeyCommitment, unlockKey = TOprfFinalize(
      blindedResults,
      blindingFactor,
      accessKey
    )

    if ConstantTimeEquals(ourUnlockKeyCommitment, unlockKeyCommitment):
      return unlockKey
    else:
      guessesRemaining = allowedGuesses - attemptedGuesses
      return Error.InvalidPin(guessesRemaining)
```

If the _unlockKey_ could be recovered successfully, the client will proceed to Phase 3. Otherwise, an _InvalidPin_ error will be returned by the client.

=== Phase 3 Recovery
The following demonstrates the work a client performs to prepare for Phase 3:

```python
  def PrepareRecovery3(realms, unlockKey):
    unlockKeyTags = [MAC(16, unlockKey, "Unlock Key Tag", realm.id)
                     for realm in realms]
    return unlockKeyTags
```

A _recover3_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- unlockKeyTags#sub[i]

The following demonstrates the work a _Realm#sub[i]_ performs to process the request:

```python
  def Recovery3(state, request):
    if state.isRegistered():
      if request.version != state.version:
        return Error.VersionMismatch()

      if !ConstantTimeEquals(request.unlockKeyTags, state.unlockKeyTags):
        guessesRemaining = state.allowedGuesses - state.attemptedGuesses

        if guessesRemaining == 0:
          state.transitionToNoGuesses()

        return Error.BadUnlockKeyTag(guessesRemaining)

      state.attemptedGuesses = 0

      return Ok(state.encryptionKeyScalarShare,
                state.encryptedSecret,
                state.encryptedSecretCommitment)
    elif state.isNoGuesses():
      return Error.NoGuesses():
    elif state.isNotRegistered():
      return Error.NotRegistered()
```

An _OK_ response from this phase should always be expected to return the following information from the user's registration state:
- encryptionKeyScalarShares#sub[i]
- encryptedSecret
- encryptedSecretCommitments#sub[i]

A _BadUnlockKeyTag_ response from this phase should always be expected to return the previously determined:
- guessesRemaining

Upon receipt of _threshold_ _OK_ responses, the client can reconstruct the user's _secret_.

The following demonstrates the work a client performs to do so:

```python
  def RecoverSecret(encryptionKeySeed,
                    encryptionKeyScalarShares,
                    encryptedSecret,
                    encryptedSecretCommitments,
                    realms,
                    threshold):
    indexedEncryptionKeyScalarShares = []

    for index, (share, commitment, realm) in
      enumerate(zip(encryptionKeyScalarShares,
                    encryptedSecretCommitments,
                    realms),
                start=1):
      ourCommitment = MAC(16,
                          unlockKey,
                          "Encrypted Secret Commitment",
                          realm.id,
                          share,
                          encryptedSecret)
      if ConstantTimeEquals(ourCommitment, commitment):
        indexedEncryptionKeyScalarShares.append((index, share))

    if len(validEncryptionKeyScalarShares) < threshold:
      return Error.Assertion()

    encryptionKeyScalar = RecoverShares(indexedEncryptionKeyScalarShares)
    encryptionKey = MAC(32,
                        encryptionKeySeed,
                        "Encryption Key",
                        encryptionKeyScalar)

    secret = Decrypt(encryptionKey, encryptedSecret, 0)
    return secret
```

== Deletion
Delete is a single-phase operation that reverts a user's registration state to _NotRegistered_.

The delete operation is exposed by the client in the following form:
$ "error" = "delete"() $

/ error: \ An error in delete, such as a transient network error.

This operation does not require the user's _PIN_ as a user can always register a new secret effectively deleting any existing secrets.

=== Phase 1 Deletion

An empty _delete_ request is sent from the client to each _Realm#sub[i]_.

Upon receipt of a _delete_ request, _Realm#sub[i]_ sets the user's registration state to _NotRegistered_.

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

Hardware Realms terminate this TLS connection outside of their _trust boundary_. This allows a single load balancer to service multiple HSMs but necessitates an additional layer of secure communication between the client and the HSM. For this layer, we use the _Noise Protocol_ @Perrin_2018 with an NK-handshake pattern with the realm's _public key_. Specifically, we use the protocol name `Noise_NK_25519_ChaChaPoly_BLAKE2s`.

== Low-Entropy PINs
While the protocol provides strong security guarantees for low entropy PINs, using a higher entropy PIN provides increased security if a _threshold_ of realms was compromised.

== Salting
The _register_ and _recover_ operations accept a _userInfo_ argument that is mixed into the _salt_ before passing it to the _KDF_. Using a known constant, like the UID, for this value can prevent a malicious _Realm_ from returning a fixed _salt_ with a pre-computed password table.

= Recommended Cryptographic Algorithms <Cryptographic_Implementation>

== OPRFs
The protocol utilizes OPRFs based on 2HashDH as defined by Jarecki _et al._ @JKK14. These operations are performed over the Ristretto255 group @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023 and utilize the SHA-512 hashing algorithm @Hansen_Eastlake_2011.

== SSS
The protocol relies on a secret-sharing scheme to ensure a _Realm_ does not gain access to the user's secret. We utilize the scheme defined by Shamir @Shamir_1979 over the Ristretto255 group @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023.

=== T-OPRFs
The protocol utilizes T-OPRFs based on 2HashTDH as defined by Jarecki _et al._ @JKKX17. These operations are performed over the Ristretto255 group @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023 and utilize the SHA-512 hashing algorithm @Hansen_Eastlake_2011.

== Robust OPRFs with ZKPs
The protocol utilizes ZKPs to allow a client to verify the server used a specific private key during the execution of the protocol. Our implementation of these proofs specifically utilizes a Chaum-Pedersen DLEQ with a Fiat-Shamir transform, as defined by Jarecki _et al._ @JKK14. These operations are performed over the Ristretto255 group @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023 and utilize the SHA-512 hashing algorithm @Hansen_Eastlake_2011.

== DSA
The protocol utilizes a cryptographic signature to validate the public key used by each _realm_. We utilize Ed25519, an Edwards-curve Digital Signature Algorithm (EdDSA) @Josefsson_Liusvaara_2017.

== KDF
The protocol relies on a _KDF_ function to add entropy to the user's _PIN_. When an expensive _KDF_ is utilized, this provides an additional layer of protection for low entropy PINs if a _threshold_ of realms were to be compromised. For this reason, we utilize _Argon2_ @Biryukov_Dinu_Khovratovich_2015.

Determining the appropriate configuration parameters for Argon2 is highly dependent on the limitations of your client hardware. Additionally, since users may register and recover secrets across multiple devices, a given user is specifically limited by the weakest device they expect to use. An intelligent client could potentially adjust a user's hashing strength based on the performance of their registered devices. This only works if you can assure new devices for that user only get more performant, which may be difficult to guarantee.

For the common case, we have evaluated performance across popular smartphones and browsers circa 2019 and defined the following recommended parameters: #footnote[Parts of this evaluation were performed in 2019 at the Signal Foundation as part of their Secure Value Recovery project.]
- Utilize Argon2id to defend against timing and GPU attacks
- Utilize parallelism of 1 (limited primarily by browser-based threading)
- Utilize 32 iterations
- Utilize 16 KiB of memory (limited primarily by low-end Android devices)

We believe this combination of parameters provides a reasonable balance between performance — a user will not wait minutes to register a secret — and security.

A client may always re-register utilizing new parameters to provide stronger guarantees in the future.

== Secret Encryption
The protocol relies on an authenticated _Encrypt_ and _Decrypt_ function to ensure that the user's PIN is required to access the secret value, even if secret shares are compromised. We utilize _ChaCha20_ and _Poly1305_ @Nir_Langley_2015.

== MAC
The protocol relies on a _MAC_ function to compute various values for future validation. We utilize _BLAKE2s-MAC-256_ @Saarinen_Aumasson_2015.

= Acknowledgments
- The protocol is heavily based on design and feedback from Trevor Perrin and Moxie Marlinspike.
- Some of the ideas utilized in this design were first suggested by the Signal Foundation in the future-looking portion of their _"Secure Value Recovery"_ blog post @Lund_2019.

= References
