extern crate alloc;

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek as x25519;

use super::{ChainingKey, HandshakeHash, Payload, Role};
pub use super::{EncryptionError, HandshakeRequest, HandshakeResponse, Transport};

// The tests need to be able to set the ephemeral secret key to produce
// deterministic results.
#[cfg(not(test))]
type EphemeralSecret = x25519::ReusableSecret;
#[cfg(test)]
type EphemeralSecret = x25519::StaticSecret;

/// Client state for an active Noise NK handshake.
pub struct Handshake {
    client_ephemeral_secret: EphemeralSecret,
    h: HandshakeHash,
    ck: ChainingKey,
}

#[derive(Debug)]
pub enum HandshakeError {
    InvalidServerKey,
    Decryption,
    Encryption,
}

impl Handshake {
    /// Called when the client wishes to open a new connection to the server.
    ///
    /// The `request` may be empty. Note that any request given here will not
    /// have forward secrecy.
    pub fn start<R: RngCore + CryptoRng>(
        server_static_public: &x25519::PublicKey,
        payload_plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(Self, HandshakeRequest), HandshakeError> {
        Self::start_with_secret(
            EphemeralSecret::new(rng),
            server_static_public,
            &[],
            payload_plaintext,
        )
    }

    /// This is split from [`start`] for testing.
    pub(super) fn start_with_secret(
        client_ephemeral_secret: EphemeralSecret,
        server_static_public: &x25519::PublicKey,
        prologue: &[u8],
        payload_plaintext: &[u8],
    ) -> Result<(Self, HandshakeRequest), HandshakeError> {
        let client_ephemeral_public = x25519::PublicKey::from(&client_ephemeral_secret);

        let (mut h, mut ck) = HandshakeHash::new();
        h.mix_hash(prologue);
        h.mix_hash(server_static_public.as_bytes());
        h.mix_hash(client_ephemeral_public.as_bytes());

        let mut cipher = ck.mix_key(&client_ephemeral_secret.diffie_hellman(server_static_public));
        let payload_ciphertext = cipher
            .encrypt_with_ad(Payload {
                msg: payload_plaintext,
                aad: &h.0,
            })
            .map_err(|_| HandshakeError::Encryption)?;
        h.mix_hash(&payload_ciphertext);

        Ok((
            Self {
                client_ephemeral_secret,
                h,
                ck,
            },
            HandshakeRequest {
                client_ephemeral_public: client_ephemeral_public.to_bytes().to_vec(),
                payload_ciphertext,
            },
        ))
    }

    /// Called when the client receives a handshake response from the server.
    ///
    /// Part of a successful response is a payload from the server, which may
    /// be empty.
    pub fn finish(
        self,
        response: &HandshakeResponse,
    ) -> Result<(Transport, Vec<u8>), HandshakeError> {
        let Self {
            client_ephemeral_secret,
            mut h,
            mut ck,
        } = self;

        let server_ephemeral_public = {
            if response.server_ephemeral_public.len() != 32 {
                return Err(HandshakeError::InvalidServerKey);
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&response.server_ephemeral_public);
            x25519::PublicKey::from(buf)
        };
        h.mix_hash(server_ephemeral_public.as_bytes());

        let mut cipher =
            ck.mix_key(&client_ephemeral_secret.diffie_hellman(&server_ephemeral_public));
        let payload_plaintext = cipher
            .decrypt_with_ad(Payload {
                msg: &response.payload_ciphertext,
                aad: &h.0,
            })
            .map_err(|_| HandshakeError::Decryption)?;

        Ok((ck.split(Role::Client), payload_plaintext))
    }
}
