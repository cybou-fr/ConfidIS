//! WebAssembly bindings for `confidis-crypto`.
//!
//! Exposed to JavaScript via `wasm-bindgen`. This crate is the thin bridge between
//! the in-browser wallet and the underlying Rust crypto. **No business
//! logic lives here** — every function delegates to `confidis-crypto` and returns
//! string-form outputs (hex / mnemonic / base64) suitable for `postMessage`
//! between the main thread and a Web Worker.
//!
//! ## Threat model contract
//!
//! - Private key bytes never cross the JS boundary in plaintext form. The wallet
//!   keeps a *handle* on the main thread and a *plaintext key inside the Worker*
//!   produced from [`vault_open`]. All signing happens inside the Worker by
//!   calling [`sign_with_signing_key_hex`].
//! - Argon2id parameters are passed in by the caller so the Worker can negotiate
//!   them at vault creation; defaults are exposed as constants.
//! - Functions return `Result<_, JsValue>` so JavaScript receives proper
//!   exceptions rather than silent failures.
//!
//! ## Build targets
//!
//! The entire `wasm-bindgen` API surface is gated behind
//! `#[cfg(target_arch = "wasm32")]`. On native targets the crate still compiles
//! as an `rlib` so the workspace `cargo build` / `cargo check` smoke-tests pass,
//! but no wasm-bindgen symbols exist. Native tests are intentionally minimal —
//! the actual logic lives in `confidis-crypto` and is tested there. Browser-side
//! behaviour is exercised via `wasm-bindgen-test` in `tests/browser.rs`.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

#[cfg(target_arch = "wasm32")]
mod wasm_api {
    use confidis_crypto::{
        Argon2idParams, VAULT_ARGON2_ITERATIONS, VAULT_ARGON2_MEMORY_KIB, VAULT_ARGON2_OUTPUT_LEN,
        VAULT_ARGON2_PARALLELISM, argon2id_derive, blake3_hex, generate_mnemonic_24_words,
        generate_vault_salt, open_vault, seal_vault, sign_hex, signing_key_from_hex,
        signing_key_from_mnemonic, signing_key_to_hex, validate_mnemonic, verify_hex,
        verifying_key_from_hex, verifying_key_to_hex,
    };
    use wasm_bindgen::prelude::*;

    // -----------------------------------------------------------------------
    // Module startup — no-op start hook (callers may install their own
    // `console_error_panic_hook`).
    // -----------------------------------------------------------------------

    #[wasm_bindgen(start)]
    pub fn _start() {}

    // -----------------------------------------------------------------------
    // Default Argon2id parameters
    // -----------------------------------------------------------------------

    /// Default Argon2id memory cost in kibibytes (64 MiB).
    #[wasm_bindgen(js_name = defaultArgon2MemoryKib)]
    pub fn default_argon2_memory_kib() -> u32 {
        VAULT_ARGON2_MEMORY_KIB
    }

    /// Default Argon2id iteration count.
    #[wasm_bindgen(js_name = defaultArgon2Iterations)]
    pub fn default_argon2_iterations() -> u32 {
        VAULT_ARGON2_ITERATIONS
    }

    /// Default Argon2id parallelism (lanes).
    #[wasm_bindgen(js_name = defaultArgon2Parallelism)]
    pub fn default_argon2_parallelism() -> u32 {
        VAULT_ARGON2_PARALLELISM
    }

    /// Default Argon2id output length in bytes.
    #[wasm_bindgen(js_name = defaultArgon2OutputLen)]
    pub fn default_argon2_output_len() -> usize {
        VAULT_ARGON2_OUTPUT_LEN
    }

    // -----------------------------------------------------------------------
    // BIP39 mnemonic
    // -----------------------------------------------------------------------

    /// Generate a fresh 24-word BIP39 mnemonic (English wordlist). Returns the
    /// space-separated phrase. Caller is responsible for displaying it to the
    /// user exactly once and never persisting it.
    #[wasm_bindgen(js_name = generateMnemonic24)]
    pub fn generate_mnemonic_24() -> Result<String, JsValue> {
        generate_mnemonic_24_words().map_err(to_js_error)
    }

    /// Validate a BIP39 mnemonic against the English wordlist and checksum.
    /// Returns `true` only when the mnemonic is well-formed.
    #[wasm_bindgen(js_name = isMnemonicValid)]
    pub fn is_mnemonic_valid(mnemonic: &str) -> bool {
        validate_mnemonic(mnemonic).is_ok()
    }

    /// Derive the hex-encoded Ed25519 signing key from a BIP39 mnemonic and
    /// optional passphrase. Pass an empty string for `passphrase` if no extra
    /// secret is used.
    ///
    /// **Worker-only**: the returned hex string contains the full private key
    /// material. It must not be exposed to the main thread.
    #[wasm_bindgen(js_name = signingKeyFromMnemonic)]
    pub fn signing_key_from_mnemonic_js(
        mnemonic: &str,
        passphrase: &str,
    ) -> Result<String, JsValue> {
        let key = signing_key_from_mnemonic(mnemonic, passphrase).map_err(to_js_error)?;
        Ok(signing_key_to_hex(&key))
    }

    /// Derive the hex-encoded Ed25519 public key from a hex-encoded signing key.
    #[wasm_bindgen(js_name = verifyingKeyFromSigningKey)]
    pub fn verifying_key_from_signing_key(signing_key_hex: &str) -> Result<String, JsValue> {
        let key = signing_key_from_hex(signing_key_hex).map_err(to_js_error)?;
        Ok(verifying_key_to_hex(&key.verifying_key()))
    }

    // -----------------------------------------------------------------------
    // Sign / verify
    // -----------------------------------------------------------------------

    /// Sign an arbitrary message with the given hex-encoded Ed25519 signing key.
    /// Returns the 64-byte signature as hex.
    #[wasm_bindgen(js_name = signWithSigningKey)]
    pub fn sign_with_signing_key_hex(
        signing_key_hex: &str,
        message: &[u8],
    ) -> Result<String, JsValue> {
        let key = signing_key_from_hex(signing_key_hex).map_err(to_js_error)?;
        Ok(sign_hex(&key, message))
    }

    /// Verify a hex-encoded Ed25519 signature against `message` and a hex-encoded
    /// public key. Returns `true` only on a valid signature.
    #[wasm_bindgen(js_name = verifyWithVerifyingKey)]
    pub fn verify_with_verifying_key_hex(
        verifying_key_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool, JsValue> {
        let key = verifying_key_from_hex(verifying_key_hex).map_err(to_js_error)?;
        Ok(verify_hex(&key, message, signature_hex).is_ok())
    }

    // -----------------------------------------------------------------------
    // Argon2id raw KDF
    // -----------------------------------------------------------------------

    /// Derive a symmetric key from a password and salt using Argon2id.
    /// Returns the raw derived key bytes (caller chooses how to encode for storage).
    ///
    /// `memory_kib`, `iterations`, `parallelism`, `output_len` MUST be set to the
    /// values that will be persisted alongside the vault so unlocks reproduce the
    /// same derivation.
    #[wasm_bindgen(js_name = argon2idDerive)]
    pub fn argon2id_derive_js(
        password: &[u8],
        salt: &[u8],
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        output_len: usize,
    ) -> Result<Vec<u8>, JsValue> {
        let params = Argon2idParams {
            memory_kib,
            iterations,
            parallelism,
            output_len,
        };
        argon2id_derive(password, salt, params).map_err(to_js_error)
    }

    // -----------------------------------------------------------------------
    // Vault seal / open — high-level helpers matching the wallet flow
    // -----------------------------------------------------------------------

    /// Generate a fresh 16-byte salt suitable for [`vault_seal`]. Caller MUST
    /// persist this salt alongside the ciphertext.
    #[wasm_bindgen(js_name = generateVaultSalt)]
    pub fn generate_vault_salt_js() -> Vec<u8> {
        generate_vault_salt().to_vec()
    }

    /// Seal arbitrary plaintext key material (typically the 32-byte Ed25519
    /// signing key bytes) with a password-derived Argon2id key + ChaCha20-Poly1305
    /// AEAD. Returns the ciphertext (nonce-prefixed). The caller persists the
    /// ciphertext and the salt to IndexedDB; on unlock both are passed back to
    /// [`vault_open`].
    #[wasm_bindgen(js_name = vaultSeal)]
    pub fn vault_seal(password: &[u8], salt: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        seal_vault(password, salt, plaintext).map_err(to_js_error)
    }

    /// Inverse of [`vault_seal`]. Wrong password, wrong salt or tampered ciphertext
    /// all surface as an opaque error — the caller MUST NOT distinguish them in UI
    /// or log output.
    #[wasm_bindgen(js_name = vaultOpen)]
    pub fn vault_open(password: &[u8], salt: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        open_vault(password, salt, ciphertext).map_err(to_js_error)
    }

    // -----------------------------------------------------------------------
    // Convenience hex helpers
    // -----------------------------------------------------------------------

    /// Encode arbitrary bytes as lowercase hex.
    #[wasm_bindgen(js_name = bytesToHex)]
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Compute the BLAKE3 hash of arbitrary bytes and return it as 64 hex chars.
    /// Used by the wallet to compute digests embedded in owner-signed and
    /// operator-signed protocol payloads. The node side recomputes digests and
    /// rejects any mismatch.
    #[wasm_bindgen(js_name = blake3Hex)]
    pub fn blake3_hex_js(bytes: &[u8]) -> String {
        blake3_hex(bytes)
    }

    /// Decode a hex string into bytes. Throws on invalid input.
    #[wasm_bindgen(js_name = hexToBytes)]
    pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, JsValue> {
        hex::decode(s).map_err(|e| JsValue::from_str(&format!("invalid hex: {e}")))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn to_js_error(err: anyhow::Error) -> JsValue {
        // We expose the message verbatim — `confidis-crypto` is careful to keep
        // error strings non-leaky (e.g. "failed to decrypt" rather than
        // distinguishing wrong-password from tampered-ciphertext).
        JsValue::from_str(&format!("{err}"))
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_api::*;

// On native targets the crate is an empty rlib. The underlying crypto logic is
// already tested in `confidis-crypto` so we do not duplicate coverage here.
#[cfg(not(target_arch = "wasm32"))]
mod native_smoke_test {
    //! Tiny native compile-time smoke check — verifies that everything in
    //! `confidis-crypto` we depend on is still resolvable. Runs as a `#[test]` on
    //! the host target so `cargo test` produces output but does not exercise
    //! `wasm-bindgen`.

    #[test]
    fn confidis_crypto_smoke_compile() {
        use confidis_crypto::{Argon2idParams, generate_mnemonic_24_words, generate_vault_salt};
        // Just touch the symbols and exercise the trivial paths.
        let _ = generate_mnemonic_24_words().unwrap();
        let _ = generate_vault_salt();
        let _ = Argon2idParams::default();
    }

    #[test]
    fn wallet_key_round_trip_matches_wasm_contract() {
        use confidis_crypto::{
            generate_mnemonic_24_words, sign_hex, signing_key_from_mnemonic, signing_key_to_hex,
            verify_hex, verifying_key_from_hex, verifying_key_to_hex,
        };

        let mnemonic = generate_mnemonic_24_words().expect("mnemonic");
        let signing_key = signing_key_from_mnemonic(&mnemonic, "").expect("signing key");
        let signing_key_hex = signing_key_to_hex(&signing_key);
        let verifying_key_hex = verifying_key_to_hex(&signing_key.verifying_key());
        let message = b"confidis wasm wallet contract";
        let signature = sign_hex(&signing_key, message);
        let verifying_key = verifying_key_from_hex(&verifying_key_hex).expect("verifying key");

        assert_eq!(signing_key_hex.len(), 64);
        assert_eq!(verifying_key_hex.len(), 64);
        assert_eq!(signature.len(), 128);
        verify_hex(&verifying_key, message, &signature).expect("signature verifies");
        assert!(verify_hex(&verifying_key, b"tampered", &signature).is_err());
    }

    #[test]
    fn vault_seal_open_round_trip_matches_wasm_contract() {
        use confidis_crypto::{generate_vault_salt, open_vault, seal_vault};

        let password = b"correct horse battery staple";
        let salt = generate_vault_salt();
        let plaintext_key = [42u8; 32];

        let ciphertext = seal_vault(password, &salt, &plaintext_key).expect("seal");
        let opened = open_vault(password, &salt, &ciphertext).expect("open");

        assert_ne!(ciphertext, plaintext_key);
        assert_eq!(opened, plaintext_key);
        assert!(open_vault(b"wrong password", &salt, &ciphertext).is_err());
    }
}
