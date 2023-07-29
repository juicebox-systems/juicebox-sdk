 An implementation of the Noise NK protocol for encrypted communication.

 [Noise](https://noiseprotocol.org/) is a framework that defines a bunch of
 related protocols for secure communication. This module implements the
 Noise NK protocol only. Noise NK has a simple message pattern that allows
 the handshake to complete after a single request and response. This code
 has very few branches by focusing on just Noise NK, compared to a
 general-purpose implementation of all the Noise protocols.

 This module is currently limited to `Noise_NK_25519_ChaChaPoly_BLAKE2s`
 specifically, which is probably what you'd want to use when doing
 cryptography in software in 32-bit mode.

 This module takes some minor liberties compared to the Noise spec:

 - Noise uses the terminology 'initiator' and 'responder', whereas this
   module names the roles 'client' and 'server'.
 - Noise simply concatenates binary fields to form messages, whereas this
   module it up to the caller to either concatenate them or encode them some
   other way.
 - Noise limits messages to 65535 bytes, whereas this module does not.
