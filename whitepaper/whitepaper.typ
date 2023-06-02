#import "template.typ": whitepaper

#show: whitepaper.with(
  title: "Juicebox Protocol",
  subtitle: "Distributed Storage and Recovery of Secret Values Using Simple PIN Authentication",
  authors: (
    (name: "Nora Trapp", affiliation: "Juicebox Systems, Inc"),
    (name: "Diego Ongaro", affiliation: "Juicebox Systems, Inc"),
  ),
  date: "June 2, 2023",
  version: "Revision 1",
  abstract: [Ensuring high adoption of privacy software requires simplicity. Unfortunately, existing secret management techniques often demand users memorize complex passwords, store convoluted recovery phrases, or place their trust in a specific service or hardware provider. We have implemented a novel protocol that combines existing cryptographic techniques to eliminate these complications and reduce user complexity to recalling a 4-digit PIN. Our protocol specifically focuses on a distributed approach to secret storage that leverages _Oblivious Pseudo Random Functions_ (OPRFs) and _Shamir's Secret Sharing_ (SSS) to minimize the trust placed in any singular server. Additionally, our approach allows for servers to be controlled by any number of organizations eliminating the need to trust a singular service operator.],
  bibliography-file: "references.bib",
)

= Introduction
At its core, the _Juicebox Protocol_ is a specification for performing secret management operations distributed across a set of _Realms_.

Specifically, the protocol aims to:
+ Never give any _Realm_ access to secret values
+ Keep user burden simple by allowing recovery through low-entropy PINs
+ Eliminate the need to trust any singular _Realm_ operator or hardware vendor

Additionaly, a key feature of the protocol is that anyone can implement and run instances that conform to it, allowing for distributed trust across different organizational boundaries.

Juicebox provides open source reference implementations for both the client and server on their github @Juicebox_Github.

= Overview

== Realms <Realms>
For the purposes of this paper, we will refer to each server that a secret can be distributed to as an abstract _Realm_. Fundamentally, each _Realm_ must adhere to the core protocol as defined here in order to be compatible. However, different realms may provide different security gurantees influencing the overall security of a user's secret value.

Each _Realm_ is assigned a unique 16-byte identifier known as a _Realm#sub[id]_. For implementation purposes, this could be any value as long as it is universally unique across realms in your configuration.

Additionally, realms have the option to generate a 32-byte EC25519 key pair which is used for encrypted communication via Noise, as described in @Noise

A _Realm_ is controlled by an _operator_ — the organization or individual who runs the service. The level of trust that must be placed in a given operator varies based on the underlying realm implementation.

It should generally be assumed that each _Realm_ controls only a share of a user's secret value (via SSS, as described in @SSS), and that a singular realm never has access to the full secret material. This gurantee is best achieved by ensuring a variety of realm types are used that span across multiple operators and trust boundaries.

=== Hardware Realms
One form of _Realm_ that we explored is the variant backed by secure hardware, such as a hardware security module (HSM). Realms of this nature allow for a significant reduction in or removal of the user's need to trust a realm's operator, as it is possible to encapsulate all protocol operations within the hardware's trusted execution environment (TEE) such that a malicious operator has no avenue of access. Additionally, it is possible to attest that a specific and verifiable version of software is being executed within the TEE.

This reduction in operator trust does not come for free — the user's trust is transitioned from the realm operator to the HSM vendor. Additionally, HSMs come with significant tradeoffs in terms of acquistion and operation cost as well as performance when compared to commodity hardware. This makes any singular HSM product insufficient as a standalone secret storage solution at scale. However, when used in concert with other types of realms — including hardware realms from other vendors — we believe the inclusion of hardware realms can provide a significant increase in security.

=== Software Realms
Another form of _Realm_ that we explored is a light weight software solution that can be easily hosted in common cloud providers. Realms of this nature allow focus on ease of deployment, facilitating further distrubition across organizational boundaries. This can be incredibly convenient to augment the costly hardware realms, reducing trust placed on any individual hardware vendor, and even allowing a single organization to operate multiple realms with different trust boundaries.

The software realms we specifically explored by design do not attempt to limit the user's need to trust the operator, and additionally require placing some degree of trust in the hosting or database provider. Since these realms only control an encrypted share of a user's secret value, we believe this is an acceptable tradeoff for the increased accessibility it provides.

It is also important to recognize that given the limited number of distinct cloud providers currently operating, over use of such realms can potentially put too much secret information in one party's control and jepoardize user secrets.

== Tenants
In general, this protocol assumes that any given _Realm_ allows storage and recovery of secrets from users spanning multiple organizational boundaries. We refer to each of these organizational boundaries as a _tenant_, and the protocol as defined ensures that any individual tenant can only perform operations on user secrets within their organizational boundary.

We encourage this multi-tenanted approach for realms, as we believe it enables a network effect that will broaden adoption of the protocol. For example, realm operator _Alice_'s users no longer must trust _Alice_ if _Alice_ additionally distributes their secrets to realm operator _Bob_'s realm. To facilitate this exchange, _Alice_ could allow _Bob_'s organization to distribute their user secrets to her realm.

This model can also potentially reduce the costs of running expensive hardware realms by distributing the costs of operation across multiple tenants.

== Oblivious Pseudrandom Functions (OPRFs)
An OPRF is a cryptographic primitive that enables a client to securely evaluate a function on a server's input, while ensuring the server learns nothing about the client's input and the client learns nothing about the server's input beyond the output of the function.

Our protocol specifically utilizes OPRFs as described in the working draft by Davidson _et al._ @Davidson_Faz-Hernandez_Sullivan_Wood_2023 as one part of a strategy for registering and recovering secrets on a _Realm_ without revealing a user's _PIN_ to the _Realm_.

For the purposes of this paper we will define the following abstract functions which map to the corresponding operations in the working draft.

/ $"OprfDeriveKey"("seed")$: Returns an OPRF _key_ derived from the provided _seed_. The key generated from a specific seed will always be the same.
/ $"OprfBlind"("input")$: Performs the blinding step for the _input_ value and returns the _blindedInput_. This message is sent from the client to the server.
/ $"OprfBlindEvaluate"("key", "blindedInput")$: Performs the evaluation step for the _blindedInput_ and returns the _blindedResult_. This message is sent from the server to the client.
/ $"OprfFinalize"("blindedResult", "input")$: Performs the finalization step to unblind the _blindedResult_ and returns the _result_.
/ $"OprfEvaluate"("key", "accessKey")$: Computes the unblinded _result_ directly bypassing the blinded exchange.

== Shamir's Secret Sharing (SSS) <SSS>
Shamir's Secret Sharing @Shamir_1979 is a cryptographic algorithm that allows a secret to be divided into multiple shares, which are then distributed among different participants. Only by collecting a minimum number of shares — typically determined by a _threshold_ specified during share creation — can the original secret be reconstructed. This approach provides a way to securely distribute and protect sensitive information by splitting it into multiple fragments that individually reveal nothing about the original secret.

For our purposes, we will define the following abstract functions for creating and reconstructing shares using this algorithm:

/ $"CreateShares"("threshold", "secret")$: Distributes _secret_ into _N_ _shares_
/ $"RecoverShares"("shares")$: Recovers _secret_ from _N_ _shares_ or returns an error if less than _threshold_ _shares_ were recovered

== Noise Protocol <Noise>
In some implementations of the _Juicebox Protocol_, such as when utilizing a _Hardware Realm_, it can be necessary to implement additional abstraction layers in communication between the user and the realm software. These additional hops introduce the potential for replay of client requests by intermediary parties, potentially allowing a malicious server to make recovery attempts against a user's _secret_.

In order to prevent replay of requests, the _Juicebox Protocol_ allows for realms to optionally share a 32-byte EC25519 key pair and distribute the public key to its clients. The realm may then implement the NK-handshake pattern of the Noise Protocol @Perrin_2018. Utilizing this pre-shared key allows users to establish a secure session directly with the realm software and encrypt each request with a new ephemeral key, regardless of additional hops a request may take to arrive at the _Realm_.

= Protocol
The _Juicebox Protocol_ can be abstracted to three simple operations — _register_, _recover_, and _delete_. These operations, as well as several prerequisites for performing them, are outlined below.

Protocol clients are expected to be configured with _n_ mutually distrusting realms, each of which will be referred to as _Realm#sub[i]_ for here on. The overall security benefits of the protocol are dependent on sufficient distribution across trust domains.

== Authentication
In order to enforce _Tenant_ boundaries, a given _Realm#sub[i]_ requires authentication proving that a user has permission to perform operations.

A _Realm#sub[i]_ aims to know as little as possible about users, an consequently relies on individual tenants to determine whether or not a user is allowed to perform a given operation.

In order to cede this control to tenants, a realm _operator_ must generate a random 32-byte signing key for each _tenant_ they wish to access their _Realm#sub[i]_. This signing key should be provided an integer version _v_ and the tenant should be provided a consistent alphanumeric name _tenantName_ that is shared by both the realm _operator_ and the _tenant_.

Given this information, a _tenant_ must vend a signed JSON Web Token (JWT) @Jones_Bradley_Sakimura_2015 in order to grant a given user access to the realm.

The header of this JWT must contain a _kid_ field of _tenantName:v_ so that the _Realm#sub[i]_ knows which version _v_ of _tenantName_'s signing key to validate against.

The claims of this JWT must contain an _iss_ field equivalent to _tenantName_ and a _sub_ field that represents a persistent user identifer (UID) the realm can use for storing secrets. Additionally, an _aud_ field must be present and contain a single hex-string equivalent to the _Realm#sub[i(id)]_ a token is valid for.

A _Realm#sub[i]_ must reject any connections that:
+ Don't contain an authentication token
+ Aren't signed with a known signing key for a given _tenantName_ and version _v_ matching the _kid_
+ Don't have an _aud_ exactly matching their _Realm#sub[i(id)]_

From this point forward, this paper will assume all requests contain valid authentication tokens for a given _Realm#sub[i]_ or that an _InvalidAuthentication_ (401) error is returned by the _Realm_.

== Additional External Functions
In addition to the previously established _OPRF_ and _SSS_ functions, the following additional functions are necessary to define the protocol:

/ $"Encrypt"("encryptionKey", "plaintext", "nonce")$: Returns an AEAD encryption of _plaintext_ with _encryptionKey_. The encryption is performed with the given _nonce_.
/ $"Decrypt"("encryptionKey", "ciphertext", "nonce")$: Returns the AEAD decryption of _ciphertext_ with _encryptionKey_. The decryption is performed with the given _nonce_.
/ $"Hash"("data", "salt")$: Returns a fixed 64-byte value that is unique to the input _data_ and _salt_.
/ $"MAC"("key", "input")$: Returns a 32-byte tag by combining the _key_ with the provided _input_.
/ $"Random"(n)$: Returns _n_ random bytes. The _Random_ function should ensure the generation of random data with high entropy, suitable for cryptographic purposes.

Recommendations on implementing these functions can be found in @Cryptographic_Implementation

== Storage
_Realm#sub[i]_ will store a record indexed by the combination of the registering user's identifier (UID) and their _tenant_. This ensures that a given _tenant_ may only authorize operations for its own users.

This record can exist in one of three states:

/ NotRegistered: The user has no existing registration on this _Realm_. This is the default state if a user has never communicated with the _Realm_.
/ Registered: The user has registered secret information with this _Realm_ and can still attempt to restore that registration.
/ NoGuesses: The user has registered secret information with this _Realm_, but can no longer attempt to restore that registration.

A user transitions into the _NoGuesses_ state when the number of _attemptedGuesses_ on their registration equals or exceeeds their _allowedGuesses_.

In the _Registered_ state, the following additional information is stored corresponding to the registration:

/ version: a unique 16-byte value that identifies this registration across all _Realms_
/ attemptedGuesses: starts at 0 and increases on recovery attempts, then reset to 0 on successful recoveries
/ allowedGuesses: the maximum number of guesses allowed before the registration is permanently deleted by the _Realm_
/ saltShares#sub[i]: a share of the salt the client generated during registration and used to hash their _PIN_
/ oprfSeeds#sub[i]: a random OPRF seed the client generated during registration, unique to this realm and this registration
/ maskedTgkShares#sub[i]: a masked share of the tag generating key
/ unlockTags#sub[i]: the key the client provides to demonstrate knowledge of the PIN and release _encryptedSecretShares#sub[i]_
/ encryptedSecretShares#sub[i]: a share of the user's encrypted secret

Standalone, none of the values stored in the _Registered_ state expose sensitive user secrets and can be stored by the _Realm_ as they see fit for their trust model. This constraint depends on realms existing across trust boundaries to prevent recovery of secret shared values.

== Registration
Registration is a two-phase process that a new user takes to store a PIN-protected secret.

A reference client might expose registration in the following form:

$ "register"("pin", "secret", "allowedGuesses", "threshold") $

/ pin: represents a low entropy value known to the user that will be used to recover their secret, such as a 4-digit pin
/ secret: represents the secret value a user wishes to persist
/ allowedGuesses: specifies the number of failed attempts a user can make to recover their secret before it is permanently deleted
/ threshold: represents the number of realms that shares must be recovered from in order for the _secret_ to be recovered. it is generally recommended that $"threshold">n/2$ where _n_ is the number of realms you are distributing to. we additionally recommend a $"threshold">=3$

=== Phase 1
An empty _register1_ request is sent from the client to each _Realm#sub[i]_.

For realms that expose a _public key_ and implement _Noise_, this request performs the handshake and establishes a _Noise_ session prior to any sensitive information being transmitted in subsequent phases.

For realms that don't implement _Noise_, this request has no operation. A client implementation could choose to optimize their behavior by skipping this phase for a given _Realm#sub[i]_ that has no _public key_.

A _Realm_ should always be expected to respond _OK_ to this request, unless the Noise handshake fails or a transient network error occurs.

=== Phase 2

Provided a client has completed _Phase 1_ (or decided it was safe to omit), the client can proceed to prepare the registration material that will be stored on each _Realm#sub[i]_. Phase 2 should not be conducted until Phase 1 is completed successfully on all realms to avoid a mismatched registration state across realms.

The client should perform the following actions:
+ Generate a random 16-byte _version_ that is used to validate registration consistency across realms
  - $"version" = "Random"(16)$
+ Generate a random 16-byte _salt_ that is used when hashing the user's _PIN_
  - $"salt" = "Random"(16)$
+ Derive an _accessKey_ and _encryptionKey_ by hashing the user's _PIN_
  - $"accessKey", "encryptionKey" = "Hash"("PIN", "salt")$
  - _accessKey_ is the first 32-bytes of the _Hash_ result
  - _encryptionKey_ is the last 32-bytes of the _Hash_ result
  - This hashing operation adds additional entropy to the user's _PIN_ before using it in _OPRF_ operations.
+ Encrypt the user's _secret_ using the derived _encryptionKey_
  - $"encryptedSecret" = "Encrypt"("secret", "encryptionKey", 0)$
  - Since a new _encryptionKey_ is used for every registration, a constant _nonce_ of zero can be safely used.
  - This serves as a low-overhead way to ensure that even if realms were to collude the user's _PIN_ is required in order to recover their _secret_. However, since a _Realm#sub[i]_ only ever should have access to a single _secret_ share this operation could technically be considered optional depending on your trust concerns.
+ Create shares of _encryptedSecret_
  - $"encryptedSecretShares" = "CreateShares"("threshold", "encryptedSecret")$
+ Generate a random 32-byte _oprfSeeds#sub[i]_ for each _Realm#sub[i]_
  - $"oprfSeeds"_i = "Random"(32)$
  - We acknowledge that it is unconventional for _OPRF_ key material to be generated on the client. However, in this instance the benefits of doing so outweigh the downsides. Specifically, this change in behavior allows it to be possible to register a secret on a realm without the additional round trip to compute the _OprfResult_. When distributed across 3 or more realms, the performance impacts of this change start to become significant. Since this protocol generally expects clients to have access to a secure random number generator capable of generating a good _oprfSeed_, the primary cause for concern becomes one of implementation and verifying that the key material is not leaked from the client before or after being provided to the _Realm_.
+ Generate a random 32-byte tag generating key _tgk_
  - $"tgk" = "Random"(32)$
  - The tag generating key is later used — in combination with the user's _accessKey_ — to validate ownership of a secret by deriving an _unlockTag_ for each _Realm#sub[i]_
+ Create shares of _tgk_
  - $"tgkShares" = "CreateShares"("threshold", "tgk")$
+ Derive the _oprfResult#sub[i]_ of _accessKey_ for each _oprfSeeds#sub[i]_
  - $"oprfResult"_i = "OprfEvaluate"("OprfDeriveKey"("oprfSeed"_i), "accessKey")$
  - Since we have the _OPRF_ key material and the _accessKey_ we can directly derive the result and skip the blinding process
+ Derive the _maskedTgkShares_
  - $"maskedTgkShares"_i = "tgkShares"_i "XOR" "oprfResult"_i$
  - This operation requires that the user to first prove they know their _PIN_ to derive the _oprfResult_ before they can unmask the _tgkShares_ and recover the _tgk_
+ Derive the _unlockTags_
  - $"unlockTag"_i = "MAC"("tgk", "Realm"_"i(id)")$
  - $"Realm"_"i(id)"$ is the unique 16-byte identifier for each _Realm#sub[i]_ as described in @Realms
  - Knowledge of this value during recovery grants the user access to their _encryptedSecretShares#sub[i]_

A _register2_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- saltShares#sub[i]
- oprfSeeds#sub[i]
- unlockTags#sub[i]
- maskedTgkShares#sub[i]
- encryptedSecretShares#sub[i]
- allowedGuesses

Upon receipt of a _register2_ request, _Realm#sub[i]_ creates or overwrites the user's registration record with the corresponding values from the request.

A _Realm_ should always be expected to respond _OK_ to this request unless a transient network error occurs.

== Recovery
Recovery is a three-phase process that a new user takes to store a PIN-protected secret.

A reference client might expose recovery in the following form:

$ "secret", "error" = "recover"("pin", "threshold" ) $

/ pin: represents the same value used during _register_
/ threshold: represents the same value used during _register_
/ secret: the recovered secret as provided during registration, if and only if the correct _pin_ was provided
/ error: indicates an error in recovery, such as an invalid _pin_ or the _allowedGuesses_ having been exceeded

=== Phase 1
An empty _recover1_ request is sent from the client to each _Realm#sub[i]_.

For realms that expose a _public key_ and implement _Noise_, this request additionally performs the handshake and establishes a _Noise_ session prior to any sensitive information being transmitted in subsequent phases.

Upon receipt of a _recover1_ request, _Realm#sub[i]_ checks the current state of a user's registration and responds appropriately.

/ NotRegistered: The _Realm_ will respond with a _NotRegistered_ error to this request.
/ Registered:
  - If $"attemptedGuesses" >= "allowedGuesses"$ on the stored registration, the _Realm_ will immediately update the record to the _NoGuesses_ state and respond appropriately.
  - Otherwise, the _Realm_ will process this request and return an _OK_ response.
/ NoGuesses: The _Realm_ will respond with a _NoGuesses_ error to this request.

An _OK_ response from this phase should always be expected to return the following information from the user's registration:
- version
- saltShares#sub[i]

=== Phase 2

Once a client has successfuly completed Phase 1 on all _Realm#sub[i]_, it must determine a majority consensus on the returned _version_ and _salt_. Only the realms that exist within this majority should be considered for the remaining phases. Provided the initial _threshold_ during registration consisted of a majority of realms, this consensus should always be reached. If this consensus cannot be reached, the client should assume that the user is _NotRegistered_.

The purpose of Phase 2 is to recover the _maskedTgkShares_ we stored during registration along with the _OPRF_ result required to unmask them and reconstruct the _tgk_. An optimal client can abort Phase 2 as soon as _threshold_ _OK_ responses are recovered, as this should be sufficient to recover the _tgk_.

The client should perform the following actions:
+ Derive an _accessKey_ and _encryptionKey_ by hashing the user's _PIN_
  - $"accessKey", "encryptionKey" = "Hash"("PIN", "salt")$
  - _accessKey_ is the first 32-bytes of the _Hash_ result
  - _encryptionKey_ is the last 32-bytes of the _Hash_ result
  - This process is identical to the one performed during registration
+ Compute _blindedAccessKeys_ for each _Realm#sub[i]_
  - $"blindedAccessKeys"_i = "OprfBlind"("accessKey")$

A _recover2_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- blindedAccessKeys#sub[i]

Upon receipt of a _recover2_ request, _Realm#sub[i]_ checks the current state of a user's registration and responds appropriately.

/ NotRegistered: The _Realm_ will respond with a _NotRegistered_ error to this request.
/ Registered:
  - If $"attemptedGuesses" >= "allowedGuesses"$ on the stored registration, the _Realm_ will immediately update the record to the _NoGuesses_ state and respond appropriately.
  - If the _version_ on the stored registration does not match the _version_ on the request, the _Realm_ will respond with a _VersionMistmatch_ error to this request.
  - Otherwise, the _Realm_ will process this request and return an _OK_ response.
/ NoGuesses: The _Realm_ will respond with a _NoGuesses_ error to this request.

The _Realm#sub[i]_ should perform the following actions to process the request:
+ Compute the _blindedResult_ using the _blindedAccessKeys#sub[i]_ from the request:
  - $"blindedResult" = "OprfBlindEvaluate"("blindedAccessKeys"_i)$
+ Increment the _attemptedGuesses_ on the stored registration as we are now revealing sensitive information about the _OPRF_ to the client that could allow them to brute force the _accessKey_ if attempts are not limited.

An _OK_ response from this phase should always be expected to return the following information:
- blindedResult
- maskedTgkShares#sub[i] _(from the user's registration record)_

=== Phase 3

Provided at least _threshold_ _OK_ responses have been received from Phase 2, a client can safely proceed to Phase 3.

The purpose of Phase 3 is to recover the _encryptedSecretShares_ allowing decryption and reconstruction of the user's _secret_. Additionally, upon success this phase resets the _attemptedGuesses_ on each _Realm#sub[i]_ to 0. For the latter reason, it is important a client completes this process on _all_ realms, even if sufficient material has been received to recover the user's _secret_.

The client should perform the following actions:
+ Compute the _oprfResults_ using the _blindedResult_ from the response and the _accessKey_ derived in Phase 2
  - $"oprfResults"_i = "OprfFinalize"("blindedResult"_i, "accessKey")$
+ Unmask the _maskedTgkShares_ from the response
  - $"tgkShares"_i = "maskedTgkShares"_i "XOR" "oprfResults"_i$
+ Recover _tgk_ from _tgkShares_
  - $"tgk" = "RecoverShares"("tgkShares")$
  - If the wrong pin was used the client will recover the wrong _tgk_
+ Derive the _unlockTags_
  - $"unlockTag"_i = "MAC"("tgk", "Realm"_"i(id)")$
  - $"Realm"_"i(id)"$ is the unique 16-byte identifier for each _Realm#sub[i]_ as described in @Realms
  - Knowledge of this value proves to the _Realm#sub[i]_ the user knows their _PIN_ and allow it to release the _encryptedSecretShare_ without revealing the _PIN_
  - If the _unlockTag#sub[i]_ is invalid due to an incorrect _PIN_ the client will not know until after confirming with _Realm#sub[i]_, ensuring both the client and the realm know the outcome of the recovery operation for any auditing purposes

A _recover3_ request is then sent from the client to each _Realm#sub[i]_ that contains the previously determined:
- version
- unlockTags#sub[i]

Upon receipt of a _recover2_ request, _Realm#sub[i]_ checks the current state of a user's registration and responds appropriately.

/ NotRegistered: The _Realm_ will respond with a _NotRegistered_ error to this request.
/ Registered:
  - If the _version_ on the stored registration does not match the _version_ on the request, the _Realm_ will respond with a _VersionMistmatch_ error to this request.
  - If the _unlockTags#sub[i]_ on the stored registration does not match the _unlockTags#sub[i]_ on the request, the _Realm_ will respond with a _BadUnlockTag_ error to this request.
  - Otherwise, the _Realm_ will process this request and return an _OK_ response.
/ NoGuesses: The _Realm_ will respond with a _NoGuesses_ error to this request.

If returning an _OK_ response, _Realm#sub[i]_ should perform the following actions:
+ Reset the _attemptedGuesses_ to 0 as the user has proven they know their _PIN_

An _OK_ response from this phase should always be expected to return the following information from the user's registration record:
- encryptedSecretShares#sub[i]

If returning a _BadUnlockTag_, _Realm#sub[i]_ should perform the following actions:
+ Compute _guessesRemaining_
  - $"guessesRemaining" = "MAX"("allowedGuesses" - "attemptedGuesses", 0)$
+ If $"guessesRemaining" = 0$ update the stored record to the _NoGuesses_ state preventing future attempts and erasing any stored material

A _BadUnlockTag_ response from this phase should always be expected to return the previously determined:
- guessesRemaining

Upon receipt of _threshold_ _OK_ responses, the client can reconstruct the user's _secret_ by performing the following actions:
+ Reconstruct _encryptedSecret_ from _encryptedSecretShares_
  - $"encryptedSecret" = "RecoverShares"("encryptedSecretShares")$
+ Decrypted _encryptedSecret_ using the previously derived _encryptionKey_ from Phase 2
  - $"secret" = "Decrypt"("encryptionKey", "encryptedSecret", 0)$

== Deletion
Delete is a single-phase process that reverts a user's registration state to _NotRegistered_.

A reference client might expose delete in the following form:
$ "delete"() $

It is important to note that _delete_ does not require the user's _pin_, since a user can always register a new secret effectively deleting any existing secrets.

=== Phase 1

An empty _delete_ request is sent from the client to each _Realm#sub[i]_.

Upon receipt of a _delete_ request _Realm#sub[i]_ sets the user's registration state to _NotRegistered_.

A _Realm_ should always be expected to responsd _OK_ to this request unless a transient network error occurs.

= Implementation Considerations

== Post-Quantum and OPRFs
While we have not performed extensive exploration into the state of post-quantum OPRFs, the data stored long-term in a user's registration at rest is sufficiently hardened against quantum attacks. Since the protocol limits replay of any requests that contain OPRF primitives, we believe it may sufficiently render such data useless in a post-quantum environment.

== Registration Generations
Earlier versions of this protocol included a concept of generations. These were needed primarily to prevent the re-use of server-derived OPRF keys, but they also allowed recovering from partial failures in registration. The current protocol does not include generations and assumes that each realm stores either 0 or 1 records per user. This approach is much simpler, but it does have a downside in the specific scenario of a user re-registering (for example, changing their PIN). If the re-registration succeeds locally but fails globally (it succeeds on some realms but not enough to reach a threshold), then the user may be unable to recover their secret using either the old or new PIN. They will need to try again later to register successfully.

= Recommended Cryptographic Algorithms <Cryptographic_Implementation>

== PIN Hashing
The protocol relies on a _Hash_ function to add entropy to the user's _PIN_. While the specific hashing algorithm is up to the client, we recommend utilizing _Argon2_ @Biryukov_Dinu_Khovratovich_2015.

Determining the appropriate configuration parameters for Argon2 is highly dependant on the limitiations of your client hardware. Additionally, since user's may register and recover secrets across multiple devices a given user is specifically limited by the weakest device they expect to use. An intelligent client could potentially adjust a user's hashing strength based on the performance of their registered devices, assuming user devices only get more performant. This is of course not a valid assumption in many common cases.

For the common case, we have evaluated performance across popular smart phones and browsers circa 2019 and determined the following recommended parameters:
- Utilize Argon2id to defend against timing and GPU attacks
- Utilize a parallelism of 1 (limited primarily by browser based threading)
- Utilize 32 iterations
- Utilize 16kbs of memory (limited primarily by low-end android devices)

We believe this combination of parameters provides a reasonable balance between performance — a user will not wait minutes to register a secret — and security.

== Secret Encryption
The protocol relies on an authenticated _Encrypt_ and _Decrypt_ function to ensure that the user's PIN is required to access the secret value, even if secret shares are compromised. While the specific encryption algorithm is up to the client, we recommend utilizing _ChaCha20_ and _Poly1305_ @Nir_Langley_2015.

== Tag MAC
The protocol relies on a _MAC_ function to compute an _unlockTag_ for a given realm. While the specific algorithm is up to the client, we recommend utilizing _BLAKE2s-256_ @Saarinen_Aumasson_2015.

== OPRF Cipher Suite
We recommend utilizing the _Ristretto255_ curve as defined by Valence _et al._ @Valence_Grigg_Hamburg_Lovecruft_Tankersley_Valsorda_2023, but other cipher suites could also be potentially suitable depending on hardware and software constraints. In particular, we recognize that certain HSMs may place restrictions on available cipher suites.

= Acknowledgements
- Trevor Perrin for helping design and review the majority of the cryptography details in the protocol
- The Signal Foundation for suggesting many of the approaches used here in the future looking portion of their _"Secure Value Recovery"_ technology preview @Lund_2019

= References
