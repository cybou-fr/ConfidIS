// Signing Worker — holds the decrypted Ed25519 signing key in process isolation.
//
// The main thread passes the signing-key hex once (on unlock) via postMessage.
// After that, signing operations are performed entirely inside this Worker;
// the key bytes never cross back to the main thread.
//
// Protocol:
//
//   main → worker  { type: "unlock",  signingKeyHex: string }
//   main → worker  { type: "sign",    id: string, payload: Uint8Array }
//   main → worker  { type: "lock" }
//
//   worker → main  { type: "ready" }           — emitted once after WASM init
//   worker → main  { type: "signed",  id: string, signature: string }
//   worker → main  { type: "error",   id: string, message: string }
//
// The Worker is created fresh per unlock session and terminated on lock(), so
// the key cannot leak to a subsequent session via module-level state.

import init, * as wasm from "confidis-crypto-wasm";

let _signingKeyHex = null;

// Initialize WASM on Worker startup; signal readiness to the main thread.
init()
  .then(() => {
    self.postMessage({ type: "ready" });
  })
  .catch((err) => {
    // If WASM fails to load the worker is unusable; propagate as a generic
    // error so unlockVault() rejects and the UI can surface it.
    self.postMessage({ type: "error", id: "__init__", message: String(err) });
  });

self.onmessage = function (e) {
  const msg = e.data;

  if (msg.type === "unlock") {
    _signingKeyHex = msg.signingKeyHex;
    return;
  }

  if (msg.type === "lock") {
    // Best-effort key erasure — JS strings are immutable; dropping the
    // reference lets the GC reclaim the backing store.
    _signingKeyHex = null;
    return;
  }

  if (msg.type === "sign") {
    const { id, payload } = msg;
    try {
      if (_signingKeyHex === null) {
        throw new Error("session verrouillée — déverrouillez le coffre pour signer");
      }
      const signature = wasm.signWithSigningKey(_signingKeyHex, payload);
      self.postMessage({ type: "signed", id, signature });
    } catch (err) {
      self.postMessage({ type: "error", id, message: err.message || String(err) });
    }
  }
};
