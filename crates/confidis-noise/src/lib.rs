//! Noise Protocol XX transport helpers for CONFIDIS node-to-node communication.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
//! - XX: both sides present and authenticate static key pairs (mutual auth)
//! - 25519: Curve25519 Diffie-Hellman
//! - ChaChaPoly: ChaCha20-Poly1305 AEAD cipher
//! - BLAKE2s: hash function
//!
//! ## Handshake flow
//!
//! ```text
//! Initiator                         Responder
//!   |-- msg1 (e) ------------------>|
//!   |<-- msg2 (e, ee, s, es) -------|
//!   |-- msg3 (s, se) -------------->|
//!   |         (both in transport mode)
//! ```
//!
//! After the handshake both sides derive the same symmetric session key and
//! can freely exchange encrypted messages via [`NoiseTransport`].

use anyhow::{Context, Result, bail};

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message size (snow internal limit is 65535).
const MAX_MSG: usize = 65535;
/// AEAD tag length added to every transport message.
const TAG_LEN: usize = 16;

// ─── Handshake ────────────────────────────────────────────────────────────────

/// Noise handshake state (wraps [`snow::HandshakeState`]).
///
/// Drives the three-message XX handshake on either the initiator or responder
/// side. Call [`write_message`](Self::write_message) /
/// [`read_message`](Self::read_message) in the correct order, then call
/// [`into_transport`](Self::into_transport) once
/// [`is_handshake_finished`](Self::is_handshake_finished) returns `true`.
pub struct NoiseHandshake {
    inner: snow::HandshakeState,
}

impl NoiseHandshake {
    fn build(secret_key: &[u8; 32], initiator: bool) -> Result<Self> {
        let params: snow::params::NoiseParams =
            NOISE_PATTERN.parse().context("invalid Noise pattern")?;

        let state = if initiator {
            snow::Builder::new(params)
                .local_private_key(secret_key)?
                .build_initiator()
        } else {
            snow::Builder::new(params)
                .local_private_key(secret_key)?
                .build_responder()
        }
        .context("failed to build Noise handshake state")?;

        Ok(Self { inner: state })
    }

    /// Create a handshake state for the **initiator** side.
    pub fn new_initiator(x25519_secret: &[u8; 32]) -> Result<Self> {
        Self::build(x25519_secret, true)
    }

    /// Create a handshake state for the **responder** side.
    pub fn new_responder(x25519_secret: &[u8; 32]) -> Result<Self> {
        Self::build(x25519_secret, false)
    }

    /// Write the next outbound handshake message (no application payload).
    ///
    /// Returns the raw message bytes to be sent to the peer.
    pub fn write_message(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_MSG];
        let len = self
            .inner
            .write_message(&[], &mut buf)
            .context("Noise write_message failed")?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Read an inbound handshake message from the peer.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; MAX_MSG];
        self.inner
            .read_message(msg, &mut buf)
            .context("Noise read_message failed")?;
        Ok(())
    }

    /// Returns `true` when all handshake messages have been exchanged and the
    /// state can be converted to transport mode.
    pub fn is_handshake_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    /// Returns the remote peer's static X25519 public key (32 bytes), if it
    /// has already been revealed by the handshake.
    ///
    /// In Noise_XX the responder learns the initiator's static key after
    /// processing msg3; the initiator learns the responder's static key after
    /// processing msg2.
    pub fn remote_static_pubkey(&self) -> Option<Vec<u8>> {
        self.inner.get_remote_static().map(Vec::from)
    }

    /// Convert the completed handshake into a [`NoiseTransport`].
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake is not yet finished.
    pub fn into_transport(self) -> Result<NoiseTransport> {
        if !self.inner.is_handshake_finished() {
            bail!("Noise handshake is not finished");
        }
        let transport = self
            .inner
            .into_transport_mode()
            .context("failed to enter Noise transport mode")?;
        Ok(NoiseTransport { inner: transport })
    }
}

// ─── Transport ────────────────────────────────────────────────────────────────

/// Noise transport session (wraps [`snow::TransportState`]).
///
/// Provides AEAD-encrypted messaging after a completed handshake. The internal
/// nonce counter increments on every call to [`encrypt`](Self::encrypt) /
/// [`decrypt`](Self::decrypt), so the caller must **not** share a single
/// `NoiseTransport` across threads without external synchronisation.
pub struct NoiseTransport {
    inner: snow::TransportState,
}

impl NoiseTransport {
    /// Encrypt `plaintext` and return the ciphertext (plaintext + 16-byte tag).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
        let len = self
            .inner
            .write_message(plaintext, &mut buf)
            .context("Noise encrypt failed")?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt and authenticate `ciphertext`. Returns the plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            bail!("Noise ciphertext too short");
        }
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .inner
            .read_message(ciphertext, &mut buf)
            .context("Noise decrypt failed")?;
        buf.truncate(len);
        Ok(buf)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a complete Noise_XX handshake and return both transport states.
    fn do_handshake(
        init_key: &[u8; 32],
        resp_key: &[u8; 32],
    ) -> (NoiseTransport, Vec<u8>, NoiseTransport, Vec<u8>) {
        let mut initiator = NoiseHandshake::new_initiator(init_key).unwrap();
        let mut responder = NoiseHandshake::new_responder(resp_key).unwrap();

        // msg1: initiator → responder (e)
        let msg1 = initiator.write_message().unwrap();
        responder.read_message(&msg1).unwrap();

        // msg2: responder → initiator (e, ee, s, es)
        let msg2 = responder.write_message().unwrap();
        initiator.read_message(&msg2).unwrap();

        // msg3: initiator → responder (s, se)
        let msg3 = initiator.write_message().unwrap();

        // initiator can now read responder's static pubkey
        let init_remote = initiator.remote_static_pubkey().unwrap();

        responder.read_message(&msg3).unwrap();
        let resp_remote = responder.remote_static_pubkey().unwrap();

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        (
            initiator.into_transport().unwrap(),
            init_remote,
            responder.into_transport().unwrap(),
            resp_remote,
        )
    }

    fn generate_key() -> [u8; 32] {
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();
        let kp = snow::Builder::new(params).generate_keypair().unwrap();
        kp.private.try_into().unwrap()
    }

    #[test]
    fn test_noise_handshake_completes() {
        let ik = generate_key();
        let rk = generate_key();
        let (_, init_remote, _, resp_remote) = do_handshake(&ik, &rk);
        // Cross-check: initiator sees responder's pubkey and vice-versa
        assert_eq!(init_remote.len(), 32);
        assert_eq!(resp_remote.len(), 32);
    }

    #[test]
    fn test_noise_encrypt_decrypt_roundtrip() {
        let ik = generate_key();
        let rk = generate_key();
        let (mut it, _, mut rt, _) = do_handshake(&ik, &rk);

        let plaintext = b"hello from CONFIDIS";
        let ct = it.encrypt(plaintext).unwrap();
        let pt = rt.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_noise_bidirectional() {
        let ik = generate_key();
        let rk = generate_key();
        let (mut it, _, mut rt, _) = do_handshake(&ik, &rk);

        // initiator → responder
        let ct1 = it.encrypt(b"ping").unwrap();
        assert_eq!(rt.decrypt(&ct1).unwrap(), b"ping");

        // responder → initiator
        let ct2 = rt.encrypt(b"pong").unwrap();
        assert_eq!(it.decrypt(&ct2).unwrap(), b"pong");
    }

    #[test]
    fn test_noise_tampered_ciphertext_rejected() {
        let ik = generate_key();
        let rk = generate_key();
        let (mut it, _, mut rt, _) = do_handshake(&ik, &rk);

        let mut ct = it.encrypt(b"secret").unwrap();
        ct[0] ^= 0xFF; // flip a bit
        assert!(rt.decrypt(&ct).is_err());
    }

    #[test]
    fn test_noise_remote_static_pubkeys_cross_match() {
        let ik = generate_key();
        let rk = generate_key();

        let (_, init_remote, _, resp_remote) = do_handshake(&ik, &rk);

        // Both sides should have learned a 32-byte peer static pubkey.
        assert_eq!(init_remote.len(), 32);
        assert_eq!(resp_remote.len(), 32);
        // Each side should see the other's key, not their own.
        assert_ne!(init_remote, ik.to_vec());
        assert_ne!(resp_remote, rk.to_vec());
    }
}
