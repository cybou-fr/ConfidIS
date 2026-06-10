use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use confidis_noise::NoiseHandshake;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::noise_session::{NoiseServerSession, NoiseServerSessionInner};
use crate::state::NodeState;
use crate::validate::{MAX_NOISE_SESSIONS, check_noise_msg_hex};

#[derive(Debug, Deserialize)]
pub(crate) struct NoiseInitiateRequest {
    /// Hex-encoded Noise_XX message 1 (initiator ephemeral pubkey).
    pub msg1: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct NoiseInitiateResponse {
    pub session_id: Uuid,
    /// Hex-encoded Noise_XX message 2 (responder ephemeral + static).
    pub msg2: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NoiseCompleteRequest {
    pub session_id: Uuid,
    /// Hex-encoded Noise_XX message 3 (initiator static).
    pub msg3: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct NoiseCompleteResponse {
    pub status: &'static str,
    /// Hex-encoded X25519 static pubkey seen for the initiator.
    pub remote_pubkey: Option<String>,
}

/// `POST /noise/initiate`
///
/// The initiator sends Noise message 1; the responder creates a session, reads
/// msg1, writes msg2, and returns both the session UUID and msg2.
pub(crate) async fn noise_initiate(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<NoiseInitiateRequest>,
) -> Result<Json<NoiseInitiateResponse>, ApiError> {
    check_noise_msg_hex(&req.msg1, "msg1")?;
    let msg1 = hex::decode(&req.msg1).map_err(|_| ApiError::bad_request("invalid msg1 hex"))?;

    let static_key = state.config.x25519_static_key.unwrap_or([0u8; 32]);

    let mut responder = NoiseHandshake::new_responder(&static_key)
        .map_err(|e| ApiError::internal(format!("Noise init failed: {e}")))?;

    responder
        .read_message(&msg1)
        .map_err(|e| ApiError::bad_request(format!("Noise msg1 rejected: {e}")))?;

    let msg2 = responder
        .write_message()
        .map_err(|e| ApiError::internal(format!("Noise msg2 failed: {e}")))?;

    let session_id = Uuid::new_v4();
    let session = Arc::new(NoiseServerSession::new(responder));

    {
        let mut sessions = state.noise_sessions.write().await;
        if sessions.len() >= MAX_NOISE_SESSIONS {
            return Err(ApiError::bad_request("too many pending noise sessions"));
        }
        sessions.insert(session_id, session);
    }

    Ok(Json(NoiseInitiateResponse {
        session_id,
        msg2: hex::encode(msg2),
    }))
}

/// `POST /noise/complete`
///
/// The initiator sends Noise message 3. The responder finalises the handshake
/// and transitions the session to transport mode.
///
/// After this call the session is ready for encrypted shard I/O.
pub(crate) async fn noise_complete(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<NoiseCompleteRequest>,
) -> Result<Json<NoiseCompleteResponse>, ApiError> {
    check_noise_msg_hex(&req.msg3, "msg3")?;
    let msg3 = hex::decode(&req.msg3).map_err(|_| ApiError::bad_request("invalid msg3 hex"))?;

    let session = {
        let sessions = state.noise_sessions.read().await;
        sessions
            .get(&req.session_id)
            .cloned()
            .ok_or_else(|| ApiError::not_found("noise session not found"))?
    };

    let mut inner = session.inner.lock().await;

    let NoiseServerSessionInner::Handshake(ref mut hs) = *inner else {
        return Err(ApiError::bad_request("session already in transport mode"));
    };

    hs.read_message(&msg3)
        .map_err(|e| ApiError::bad_request(format!("Noise msg3 rejected: {e}")))?;

    // Node participation is permissionless: the Noise handshake provides
    // transport encryption and records the initiator's static key, but it is
    // NOT an admission gate. Authority sanctions are applied reactively via the
    // signed node ban list, not at handshake time.
    let remote_pubkey = hs.remote_static_pubkey();
    let remote_pubkey_hex = remote_pubkey.as_deref().map(hex::encode);

    *session.remote_static.lock().await = remote_pubkey;

    drop(inner);
    {
        let mut inner2 = session.inner.lock().await;
        let old = std::mem::replace(
            &mut *inner2,
            NoiseServerSessionInner::Transport(
                NoiseHandshake::new_responder(&[0u8; 32])
                    .and_then(|hs| hs.into_transport())
                    .map_err(|e| ApiError::internal(format!("Noise placeholder: {e}")))?,
            ),
        );
        let NoiseServerSessionInner::Handshake(hs) = old else {
            return Err(ApiError::internal("unexpected session state after re-lock"));
        };
        let transport = (*hs)
            .into_transport()
            .map_err(|e| ApiError::internal(format!("Noise into_transport: {e}")))?;
        *inner2 = NoiseServerSessionInner::Transport(transport);
    }

    Ok(Json(NoiseCompleteResponse {
        status: "ok",
        remote_pubkey: remote_pubkey_hex,
    }))
}

/// Resolve the `x-noise-session` header to a known [`NoiseServerSession`].
pub(crate) async fn get_transport_session(
    state: &Arc<NodeState>,
    headers: &HeaderMap,
) -> Result<Arc<NoiseServerSession>, ApiError> {
    let header = headers
        .get("x-noise-session")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("missing x-noise-session header"))?;
    let session_id: Uuid = header
        .parse()
        .map_err(|_| ApiError::bad_request("invalid x-noise-session UUID"))?;
    let sessions = state.noise_sessions.read().await;
    sessions
        .get(&session_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("noise session not found or expired"))
}
