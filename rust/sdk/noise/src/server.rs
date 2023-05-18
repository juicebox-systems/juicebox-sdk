extern crate alloc;

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek as x25519;

use super::{ChainingKey, CipherState, HandshakeHash, Payload, Role};
pub use super::{EncryptionError, HandshakeRequest, HandshakeResponse, Transport};

// The tests need to be able to set the ephemeral secret key to produce
// deterministic results.
#[cfg(not(test))]
type EphemeralSecret = x25519::EphemeralSecret;
#[cfg(test)]
type EphemeralSecret = x25519::StaticSecret;

/// Server state for an active Noise NK handshake. This is created when the
/// server receives a handshake request and is only used briefly to generate
/// the server's response.
pub struct Handshake {
    cipher: CipherState,
    h: HandshakeHash,
    ck: ChainingKey,
    server_ephemeral_public: Vec<u8>,
}

#[derive(Debug)]
pub enum HandshakeError {
    InvalidClientKey,
    Decryption,
    Encryption,
}

impl Handshake {
    /// Called when the server receives a handshake request from a client.
    pub fn start<R: RngCore + CryptoRng>(
        (server_static_secret, server_static_public): (&x25519::StaticSecret, &x25519::PublicKey),
        request: &HandshakeRequest,
        rng: R,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        Self::start_with_secret(
            EphemeralSecret::random_from_rng(rng),
            (server_static_secret, server_static_public),
            &[],
            request,
        )
    }

    /// This is split from [`start`] for testing.
    pub(super) fn start_with_secret(
        server_ephemeral_secret: EphemeralSecret,
        (server_static_secret, server_static_public): (&x25519::StaticSecret, &x25519::PublicKey),
        prologue: &[u8],
        request: &HandshakeRequest,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let client_ephemeral_public = {
            if request.client_ephemeral_public.len() != 32 {
                return Err(HandshakeError::InvalidClientKey);
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&request.client_ephemeral_public);
            x25519::PublicKey::from(buf)
        };

        let (mut h, mut ck) = HandshakeHash::new();
        h.mix_hash(prologue);
        h.mix_hash(server_static_public.as_bytes());
        h.mix_hash(client_ephemeral_public.as_bytes());

        let mut cipher = ck.mix_key(&server_static_secret.diffie_hellman(&client_ephemeral_public));
        let payload_plaintext = cipher
            .decrypt_with_ad(Payload {
                msg: &request.payload_ciphertext,
                aad: &h.0,
            })
            .map_err(|_| HandshakeError::Decryption)?;
        h.mix_hash(&request.payload_ciphertext);

        let server_ephemeral_public = x25519::PublicKey::from(&server_ephemeral_secret)
            .to_bytes()
            .to_vec();
        h.mix_hash(&server_ephemeral_public);
        cipher = ck.mix_key(&server_ephemeral_secret.diffie_hellman(&client_ephemeral_public));

        Ok((
            Self {
                cipher,
                h,
                ck,
                server_ephemeral_public,
            },
            payload_plaintext,
        ))
    }

    /// Called when the server is ready to reply to the client's handshake
    /// request.
    pub fn finish(
        self,
        payload_plaintext: &[u8],
    ) -> Result<(Transport, HandshakeResponse), EncryptionError> {
        let Self {
            mut cipher,
            h,
            ck,
            server_ephemeral_public,
        } = self;
        let payload_ciphertext = cipher.encrypt_with_ad(Payload {
            msg: payload_plaintext,
            aad: &h.0,
        })?;
        Ok((
            ck.split(Role::Server),
            HandshakeResponse {
                server_ephemeral_public,
                payload_ciphertext,
            },
        ))
    }
}
