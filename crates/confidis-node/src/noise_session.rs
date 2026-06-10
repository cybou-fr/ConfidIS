//! Server-side Noise session storage types.
//!
//! Each [`NoiseServerSession`] holds either a pending [`snow::HandshakeState`]
//! (between the first two HTTP calls) or a completed [`snow::TransportState`]
//! (ready for encrypted shard transfers). A `Mutex` guards the inner state so
//! that nonce increments and state transitions are serialised.

use std::time::Instant;

use tokio::sync::Mutex;

/// Inner state of a server-side Noise session.
pub(crate) enum NoiseServerSessionInner {
    /// Handshake in progress — awaiting the initiator's third message.
    Handshake(Box<confidis_noise::NoiseHandshake>),
    /// Handshake complete — ready for encrypted shard I/O.
    Transport(confidis_noise::NoiseTransport),
}

impl std::fmt::Debug for NoiseServerSessionInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(_) => write!(f, "NoiseServerSessionInner::Handshake"),
            Self::Transport(_) => write!(f, "NoiseServerSessionInner::Transport"),
        }
    }
}

/// A server-side Noise session entry stored in [`NodeState::noise_sessions`].
#[derive(Debug)]
pub(crate) struct NoiseServerSession {
    pub(crate) inner: Mutex<NoiseServerSessionInner>,
    /// Wall-clock creation time used for TTL-based eviction.
    pub(crate) created_at: Instant,
    /// X25519 public key of the remote peer, set after the handshake completes.
    /// Used to verify the initiator against their registered `NodeMembershipCertificate`.
    pub(crate) remote_static: Mutex<Option<Vec<u8>>>,
}

impl NoiseServerSession {
    pub(crate) fn new(hs: confidis_noise::NoiseHandshake) -> Self {
        Self {
            inner: Mutex::new(NoiseServerSessionInner::Handshake(Box::new(hs))),
            created_at: Instant::now(),
            remote_static: Mutex::new(None),
        }
    }
}
