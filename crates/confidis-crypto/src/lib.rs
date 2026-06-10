use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// Domain separation tag for deriving the Ed25519 wallet key from a BIP39 seed.
/// Bumping this constant invalidates every existing wallet — do not change without
/// a documented migration path. `v1` matches the in-browser wallet released with
/// Phase 2.5.
pub const WALLET_ED25519_DERIVATION_TAG: &[u8] = b"confidis-wallet-ed25519-v1";

/// Default Argon2id parameters for vault password derivation, targeting ≥ 250 ms on a
/// 2024-era mid-tier laptop and matching the threat model § 14 figures.
/// Memory cost is expressed in kibibytes.
pub const VAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const VAULT_ARGON2_ITERATIONS: u32 = 3;
pub const VAULT_ARGON2_PARALLELISM: u32 = 1;
pub const VAULT_ARGON2_OUTPUT_LEN: usize = 32;

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn signing_key_to_hex(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

pub fn verifying_key_to_hex(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

pub fn signing_key_from_hex(encoded: &str) -> Result<SigningKey> {
    let bytes = hex::decode(encoded).context("invalid signing key hex")?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("signing key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

pub fn verifying_key_from_hex(encoded: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(encoded).context("invalid verifying key hex")?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("verifying key must be 32 bytes")?;
    VerifyingKey::from_bytes(&key_bytes).context("invalid verifying key")
}

pub fn sign_hex(key: &SigningKey, message: &[u8]) -> String {
    hex::encode(key.sign(message).to_bytes())
}

pub fn verify_hex(key: &VerifyingKey, message: &[u8], signature_hex: &str) -> Result<()> {
    let bytes = hex::decode(signature_hex).context("invalid signature hex")?;
    let sig_bytes: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .context("signature must be 64 bytes")?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(message, &signature)
        .context("signature verification failed")
}

// ---------------------------------------------------------------------------
// BIP39 mnemonic helpers
// ---------------------------------------------------------------------------

/// Generate a fresh 24-word BIP39 mnemonic in English.
///
/// 24 words encode 256 bits of entropy, matching the Ed25519 wallet key size.
/// The returned string is space-separated and case-sensitive (lowercase).
pub fn generate_mnemonic_24_words() -> Result<String> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .context("failed to encode entropy into BIP39 mnemonic")?;
    Ok(mnemonic.to_string())
}

/// Validate a BIP39 mnemonic string against the English wordlist + checksum.
/// Returns `Ok(())` only when the mnemonic is well-formed and the embedded
/// checksum matches. Used by the wallet to refuse typos before deriving a key
/// that would silently disagree with the original.
pub fn validate_mnemonic(mnemonic: &str) -> Result<()> {
    Mnemonic::parse_in(Language::English, mnemonic.trim())
        .map(|_| ())
        .context("invalid BIP39 mnemonic")
}

/// Deterministically derive the Ed25519 wallet signing key from a BIP39 mnemonic
/// and an optional passphrase. The same `(mnemonic, passphrase)` pair always
/// returns the same key on any device, which is what makes the mnemonic a true
/// recovery secret in the zero-knowledge model.
///
/// Derivation is: BIP39 mnemonic + passphrase → 64-byte PBKDF2-HMAC-SHA512 seed
/// (as defined by BIP39) → `blake3(WALLET_ED25519_DERIVATION_TAG || seed)` → 32-byte
/// Ed25519 signing key. This is intentionally CONFIDIS-specific (no cross-wallet
/// compatibility with BIP32/SLIP-0010) so a leaked mnemonic from another wallet
/// cannot trivially open a CONFIDIS wallet and vice versa.
pub fn signing_key_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<SigningKey> {
    let parsed =
        Mnemonic::parse_in(Language::English, mnemonic.trim()).context("invalid BIP39 mnemonic")?;
    let seed = parsed.to_seed(passphrase);
    let mut hasher = blake3::Hasher::new();
    hasher.update(WALLET_ED25519_DERIVATION_TAG);
    hasher.update(&seed);
    let key_bytes = *hasher.finalize().as_bytes();
    Ok(SigningKey::from_bytes(&key_bytes))
}

// ---------------------------------------------------------------------------
// Argon2id KDF for vault password encryption
// ---------------------------------------------------------------------------

/// Parameters for an Argon2id derivation. All four fields are exposed so the
/// caller can tune them at vault creation time based on runtime probing of
/// the user's device.
#[derive(Debug, Clone, Copy)]
pub struct Argon2idParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: usize,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            memory_kib: VAULT_ARGON2_MEMORY_KIB,
            iterations: VAULT_ARGON2_ITERATIONS,
            parallelism: VAULT_ARGON2_PARALLELISM,
            output_len: VAULT_ARGON2_OUTPUT_LEN,
        }
    }
}

/// Derive a symmetric encryption key from a password and salt using Argon2id.
///
/// Used by the in-browser wallet to wrap the Ed25519 signing key before
/// persisting the ciphertext in IndexedDB. Defaults are sized to take
/// ≥ 250 ms on a 2024-era mid-tier laptop (m=64 MiB, t=3, p=1, 32-byte output).
///
/// Returns a 32-byte symmetric key suitable for `ChaCha20-Poly1305`.
/// Salt MUST be at least 16 bytes and freshly random per vault (not reused).
pub fn argon2id_derive(password: &[u8], salt: &[u8], params: Argon2idParams) -> Result<Vec<u8>> {
    if salt.len() < 16 {
        anyhow::bail!("argon2id salt must be at least 16 bytes");
    }
    if params.output_len == 0 {
        anyhow::bail!("argon2id output_len must be positive");
    }
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|e| anyhow::anyhow!("invalid argon2id params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut out = vec![0u8; params.output_len];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2id derivation failed: {e}"))?;
    Ok(out)
}

/// Generate a fresh 16-byte salt for Argon2id. Caller MUST persist the salt
/// alongside the ciphertext so the vault can be re-derived on unlock.
pub fn generate_vault_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

// ---------------------------------------------------------------------------
// Vault sealing — convenience wrapper combining Argon2id + ChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// Encrypt arbitrary key material (e.g. a 32-byte Ed25519 signing key) with a
/// password-derived Argon2id key + ChaCha20-Poly1305 AEAD.
///
/// Returns ciphertext bytes prefixed with the 12-byte AEAD nonce. The caller
/// must store the returned ciphertext and the salt used for KDF; on unlock,
/// pass the same salt back to [`open_vault`].
pub fn seal_vault(password: &[u8], salt: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = argon2id_derive(password, salt, Argon2idParams::default())?;
    let key_bytes: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("argon2id key must be 32 bytes for ChaCha20-Poly1305"))?;
    encrypt_with_key(&key_bytes, plaintext)
}

/// Inverse of [`seal_vault`]. Returns the plaintext key material on success.
/// A wrong password or tampered ciphertext fails with a generic decryption
/// error and never leaks which side was wrong.
pub fn open_vault(password: &[u8], salt: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = argon2id_derive(password, salt, Argon2idParams::default())?;
    let key_bytes: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("argon2id key must be 32 bytes for ChaCha20-Poly1305"))?;
    decrypt_with_key(&key_bytes, ciphertext)
}

pub fn derive_manifest_key(secret_hex: &str) -> Result<[u8; 32]> {
    let secret = hex::decode(secret_hex).context("invalid secret hex")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"confidis-manifest-v1");
    hasher.update(&secret);
    let hash = hasher.finalize();
    Ok(*hash.as_bytes())
}

pub fn encrypt_manifest_bytes(secret_hex: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = derive_manifest_key(secret_hex)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("failed to encrypt manifest"))?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_manifest_bytes(secret_hex: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 {
        anyhow::bail!("encrypted manifest too short");
    }
    let key_bytes = derive_manifest_key(secret_hex)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let (nonce, ciphertext) = encrypted.split_at(12);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("failed to decrypt manifest"))
}

pub fn generate_cellule_key() -> [u8; 32] {
    let key = ChaCha20Poly1305::generate_key(&mut AeadOsRng);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&key);
    bytes
}

/// Generate a fresh X25519 keypair. Returns `(secret_hex, pubkey_hex)`.
/// The secret must be stored securely by the caller. The pubkey is safe to share.
pub fn x25519_generate() -> (String, String) {
    let secret = X25519Secret::random_from_rng(OsRng);
    let pubkey = X25519PublicKey::from(&secret);
    (
        hex::encode(secret.as_bytes()),
        hex::encode(pubkey.as_bytes()),
    )
}

/// Derive the X25519 public key from a hex-encoded X25519 secret key.
pub fn x25519_pubkey_from_secret_hex(secret_hex: &str) -> Result<String> {
    let bytes = hex::decode(secret_hex).context("invalid x25519 secret hex")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 secret must be 32 bytes"))?;
    let secret = X25519Secret::from(key_bytes);
    let pubkey = X25519PublicKey::from(&secret);
    Ok(hex::encode(pubkey.as_bytes()))
}

pub fn x25519_seal(recipient_pubkey_hex: &str, plaintext: &[u8]) -> Result<(String, Vec<u8>)> {
    let recipient_pubkey = x25519_public_key_from_hex(recipient_pubkey_hex)?;
    let ephemeral_secret = X25519Secret::random_from_rng(OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_pubkey);
    let key = derive_x25519_seal_key(
        shared.as_bytes(),
        ephemeral_pubkey.as_bytes(),
        recipient_pubkey.as_bytes(),
    );
    let ciphertext = encrypt_with_key(&key, plaintext)?;
    Ok((hex::encode(ephemeral_pubkey.as_bytes()), ciphertext))
}

pub fn x25519_open(
    recipient_secret_hex: &str,
    ephemeral_pubkey_hex: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let secret_bytes = hex::decode(recipient_secret_hex).context("invalid x25519 secret hex")?;
    let secret_bytes: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 secret must be 32 bytes"))?;
    let recipient_secret = X25519Secret::from(secret_bytes);
    let recipient_pubkey = X25519PublicKey::from(&recipient_secret);
    let ephemeral_pubkey = x25519_public_key_from_hex(ephemeral_pubkey_hex)?;
    let shared = recipient_secret.diffie_hellman(&ephemeral_pubkey);
    let key = derive_x25519_seal_key(
        shared.as_bytes(),
        ephemeral_pubkey.as_bytes(),
        recipient_pubkey.as_bytes(),
    );
    decrypt_with_key(&key, ciphertext)
}

fn x25519_public_key_from_hex(encoded: &str) -> Result<X25519PublicKey> {
    let bytes = hex::decode(encoded).context("invalid x25519 public key hex")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 public key must be 32 bytes"))?;
    Ok(X25519PublicKey::from(key_bytes))
}

fn derive_x25519_seal_key(
    shared_secret: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    recipient_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"confidis-x25519-seal-v1");
    hasher.update(shared_secret);
    hasher.update(ephemeral_pubkey);
    hasher.update(recipient_pubkey);
    *hasher.finalize().as_bytes()
}

pub fn derive_key_encryption_key(secret_hex: &str) -> Result<[u8; 32]> {
    let secret = hex::decode(secret_hex).context("invalid secret hex")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"confidis-cellule-key-envelope-v1");
    hasher.update(&secret);
    let hash = hasher.finalize();
    Ok(*hash.as_bytes())
}

pub fn seal_cellule_key(secret_hex: &str, cellule_key: &[u8; 32]) -> Result<Vec<u8>> {
    encrypt_with_key(&derive_key_encryption_key(secret_hex)?, cellule_key)
}

pub fn open_cellule_key(secret_hex: &str, sealed_key: &[u8]) -> Result<[u8; 32]> {
    let bytes = decrypt_with_key(&derive_key_encryption_key(secret_hex)?, sealed_key)?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("opened Cellule key must be 32 bytes")?;
    Ok(key)
}

pub fn encrypt_with_cellule_key(cellule_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_key(cellule_key, plaintext)
}

pub fn decrypt_with_cellule_key(cellule_key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    decrypt_with_key(cellule_key, encrypted)
}

pub fn derive_cellule_field_key(cellule_key: &[u8; 32], field_name: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"confidis-cellule-field-v1");
    hasher.update(cellule_key);
    hasher.update(field_name.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn encrypt_cellule_field(
    cellule_key: &[u8; 32],
    field_name: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    encrypt_with_key(
        &derive_cellule_field_key(cellule_key, field_name),
        plaintext,
    )
}

pub fn decrypt_cellule_field(
    cellule_key: &[u8; 32],
    field_name: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    decrypt_with_key(
        &derive_cellule_field_key(cellule_key, field_name),
        encrypted,
    )
}

fn encrypt_with_key(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("failed to encrypt bytes"))?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_with_key(key_bytes: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 {
        anyhow::bail!("encrypted bytes too short");
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let (nonce, ciphertext) = encrypted.split_at(12);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("failed to decrypt bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_tampering() {
        let signing_key = generate_signing_key();
        let verifying_key = signing_key.verifying_key();

        let message = b"CRITICAL_PROTOCOL_STATE_UPDATE";
        let mut signature_hex = sign_hex(&signing_key, message);

        // Valid verify should succeed
        assert!(verify_hex(&verifying_key, message, &signature_hex).is_ok());

        // Tamper with the message
        let tampered_message = b"CRITICAL_PROTOCOL_STATE_UPDATT";
        assert!(verify_hex(&verifying_key, tampered_message, &signature_hex).is_err());

        // Tamper with the signature bytes
        // We flip the last character of the hex string
        let last_char = signature_hex.pop().unwrap();
        let flipped_char = if last_char == '0' { '1' } else { '0' };
        signature_hex.push(flipped_char);

        assert!(verify_hex(&verifying_key, message, &signature_hex).is_err());
    }

    #[test]
    fn test_envelope_corruption() {
        let signing_key = generate_signing_key();
        let secret_hex = signing_key_to_hex(&signing_key);
        let plaintext = b"MANIFEST_CONTENT_123456";

        let mut encrypted = encrypt_manifest_bytes(&secret_hex, plaintext).unwrap();

        let decrypted = decrypt_manifest_bytes(&secret_hex, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        encrypted[15] ^= 0x01;
        let result = decrypt_manifest_bytes(&secret_hex, &encrypted);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "failed to decrypt manifest"
        );
    }

    #[test]
    fn manifest_key_is_deterministic() {
        let key = generate_signing_key();
        let secret = signing_key_to_hex(&key);
        let k1 = derive_manifest_key(&secret).unwrap();
        let k2 = derive_manifest_key(&secret).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn manifest_key_differs_for_different_secrets() {
        let s1 = signing_key_to_hex(&generate_signing_key());
        let s2 = signing_key_to_hex(&generate_signing_key());
        assert_ne!(
            derive_manifest_key(&s1).unwrap(),
            derive_manifest_key(&s2).unwrap()
        );
    }

    #[test]
    fn cellule_key_seal_open_roundtrip() {
        let secret = signing_key_to_hex(&generate_signing_key());
        let key = generate_cellule_key();
        let sealed = seal_cellule_key(&secret, &key).unwrap();
        let opened = open_cellule_key(&secret, &sealed).unwrap();
        assert_eq!(key, opened);
    }

    #[test]
    fn cellule_key_wrong_secret_is_rejected() {
        let secret_a = signing_key_to_hex(&generate_signing_key());
        let secret_b = signing_key_to_hex(&generate_signing_key());
        let key = generate_cellule_key();
        let sealed = seal_cellule_key(&secret_a, &key).unwrap();
        assert!(open_cellule_key(&secret_b, &sealed).is_err());
    }

    #[test]
    fn cellule_encrypt_decrypt_roundtrip() {
        let key = generate_cellule_key();
        let plaintext = b"sensitive cellule payload";
        let encrypted = encrypt_with_cellule_key(&key, plaintext).unwrap();
        let decrypted = decrypt_with_cellule_key(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn cellule_decrypt_rejects_tampered_ciphertext() {
        let key = generate_cellule_key();
        let mut encrypted = encrypt_with_cellule_key(&key, b"payload").unwrap();
        encrypted[15] ^= 0xff;
        assert!(decrypt_with_cellule_key(&key, &encrypted).is_err());
    }

    #[test]
    fn decrypt_rejects_too_short_manifest_blob() {
        let secret = signing_key_to_hex(&generate_signing_key());
        let err = decrypt_manifest_bytes(&secret, &[0u8; 11])
            .unwrap_err()
            .to_string();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn decrypt_rejects_too_short_cellule_blob() {
        let key = generate_cellule_key();
        let err = decrypt_with_cellule_key(&key, &[0u8; 11])
            .unwrap_err()
            .to_string();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn signing_key_from_hex_rejects_bad_length() {
        assert!(signing_key_from_hex("deadbeef").is_err());
    }

    #[test]
    fn signing_key_from_hex_rejects_invalid_hex() {
        assert!(signing_key_from_hex("zzzz").is_err());
    }

    #[test]
    fn verifying_key_from_hex_rejects_bad_length() {
        assert!(verifying_key_from_hex("deadbeef").is_err());
    }

    #[test]
    fn cross_key_isolation() {
        let key_a = generate_cellule_key();
        let key_b = generate_cellule_key();
        let encrypted = encrypt_with_cellule_key(&key_a, b"secret").unwrap();
        assert!(decrypt_with_cellule_key(&key_b, &encrypted).is_err());
    }

    #[test]
    fn cellule_field_encryption_is_scoped_by_field_name() {
        let key = generate_cellule_key();
        let encrypted = encrypt_cellule_field(&key, "identity.company_name", b"ACME").unwrap();
        let decrypted = decrypt_cellule_field(&key, "identity.company_name", &encrypted).unwrap();
        assert_eq!(decrypted, b"ACME");
        assert!(decrypt_cellule_field(&key, "kyc.status", &encrypted).is_err());
    }

    #[test]
    fn x25519_seal_open_roundtrip() {
        let (secret, public) = x25519_generate();
        let (ephemeral_public, ciphertext) = x25519_seal(&public, b"recipient payload").unwrap();
        let plaintext = x25519_open(&secret, &ephemeral_public, &ciphertext).unwrap();
        assert_eq!(plaintext, b"recipient payload");

        let (wrong_secret, _) = x25519_generate();
        assert!(x25519_open(&wrong_secret, &ephemeral_public, &ciphertext).is_err());
    }

    // -----------------------------------------------------------------
    // BIP39 mnemonic
    // -----------------------------------------------------------------

    #[test]
    fn generates_valid_24_word_mnemonic() {
        let m = generate_mnemonic_24_words().unwrap();
        let words: Vec<&str> = m.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        validate_mnemonic(&m).unwrap();
    }

    #[test]
    fn generated_mnemonics_are_distinct() {
        let a = generate_mnemonic_24_words().unwrap();
        let b = generate_mnemonic_24_words().unwrap();
        assert_ne!(a, b, "two random 24-word mnemonics should not collide");
    }

    #[test]
    fn validates_known_good_and_rejects_bad_mnemonic() {
        // Well-formed test vector from the BIP39 spec (24 words, valid checksum).
        let good = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        validate_mnemonic(good).unwrap();
        validate_mnemonic("not real words at all").unwrap_err();
        // Right number of words but bad checksum — last word changed.
        let bad_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(validate_mnemonic(bad_checksum).is_err());
    }

    #[test]
    fn mnemonic_derivation_is_deterministic() {
        let m = generate_mnemonic_24_words().unwrap();
        let k1 = signing_key_from_mnemonic(&m, "").unwrap();
        let k2 = signing_key_from_mnemonic(&m, "").unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn mnemonic_derivation_changes_with_passphrase() {
        let m = generate_mnemonic_24_words().unwrap();
        let k_no_pass = signing_key_from_mnemonic(&m, "").unwrap();
        let k_with_pass = signing_key_from_mnemonic(&m, "my-extra-secret").unwrap();
        assert_ne!(k_no_pass.to_bytes(), k_with_pass.to_bytes());
    }

    #[test]
    fn different_mnemonics_derive_different_keys() {
        let m1 = generate_mnemonic_24_words().unwrap();
        let m2 = generate_mnemonic_24_words().unwrap();
        let k1 = signing_key_from_mnemonic(&m1, "").unwrap();
        let k2 = signing_key_from_mnemonic(&m2, "").unwrap();
        assert_ne!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn mnemonic_derivation_is_independent_of_whitespace_padding() {
        let m = generate_mnemonic_24_words().unwrap();
        let padded = format!("   {m}\n  ");
        let k1 = signing_key_from_mnemonic(&m, "").unwrap();
        let k2 = signing_key_from_mnemonic(&padded, "").unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn derived_key_can_sign_and_verify() {
        let m = generate_mnemonic_24_words().unwrap();
        let key = signing_key_from_mnemonic(&m, "").unwrap();
        let vk = key.verifying_key();
        let sig = sign_hex(&key, b"hello confidis wallet");
        assert!(verify_hex(&vk, b"hello confidis wallet", &sig).is_ok());
    }

    // -----------------------------------------------------------------
    // Argon2id KDF and vault sealing
    // -----------------------------------------------------------------

    /// Reduced Argon2id params for fast-running tests. Production callers should
    /// always use `Argon2idParams::default()` which is calibrated for security.
    fn test_argon2_params() -> Argon2idParams {
        Argon2idParams {
            memory_kib: 8 * 1024, // 8 MiB
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        }
    }

    #[test]
    fn argon2id_derivation_is_deterministic() {
        let salt = generate_vault_salt();
        let k1 = argon2id_derive(b"password", &salt, test_argon2_params()).unwrap();
        let k2 = argon2id_derive(b"password", &salt, test_argon2_params()).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn argon2id_different_passwords_differ() {
        let salt = generate_vault_salt();
        let k1 = argon2id_derive(b"password-a", &salt, test_argon2_params()).unwrap();
        let k2 = argon2id_derive(b"password-b", &salt, test_argon2_params()).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn argon2id_different_salts_differ() {
        let salt_a = generate_vault_salt();
        let salt_b = generate_vault_salt();
        let k1 = argon2id_derive(b"password", &salt_a, test_argon2_params()).unwrap();
        let k2 = argon2id_derive(b"password", &salt_b, test_argon2_params()).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn argon2id_rejects_short_salt() {
        let short_salt = [0u8; 8];
        let err = argon2id_derive(b"pw", &short_salt, test_argon2_params()).unwrap_err();
        assert!(format!("{err}").contains("at least 16 bytes"));
    }

    #[test]
    fn vault_seal_open_roundtrip_with_test_params() {
        // We seal/open manually with reduced params for test speed.
        let salt = generate_vault_salt();
        let key =
            argon2id_derive(b"correct horse battery staple", &salt, test_argon2_params()).unwrap();
        let key_bytes: [u8; 32] = key.as_slice().try_into().unwrap();
        let mnemonic = generate_mnemonic_24_words().unwrap();
        let signing = signing_key_from_mnemonic(&mnemonic, "").unwrap();
        let plaintext = signing.to_bytes();

        let sealed = encrypt_with_key(&key_bytes, &plaintext).unwrap();
        let opened = decrypt_with_key(&key_bytes, &sealed).unwrap();
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn vault_default_seal_open_roundtrip() {
        // Uses the production Argon2id parameters once to confirm the slow path works end-to-end.
        let salt = generate_vault_salt();
        let sealed = seal_vault(b"strong password choice", &salt, b"some key material").unwrap();
        let opened = open_vault(b"strong password choice", &salt, &sealed).unwrap();
        assert_eq!(opened, b"some key material");
    }

    #[test]
    fn vault_wrong_password_rejected() {
        let salt = generate_vault_salt();
        let sealed = seal_vault(b"correct", &salt, b"key material").unwrap();
        assert!(open_vault(b"wrong", &salt, &sealed).is_err());
    }

    #[test]
    fn vault_wrong_salt_rejected() {
        let salt_a = generate_vault_salt();
        let salt_b = generate_vault_salt();
        let sealed = seal_vault(b"password", &salt_a, b"key material").unwrap();
        assert!(open_vault(b"password", &salt_b, &sealed).is_err());
    }

    #[test]
    fn vault_tampered_ciphertext_rejected() {
        let salt = generate_vault_salt();
        let mut sealed = seal_vault(b"password", &salt, b"key material").unwrap();
        sealed[15] ^= 0xff;
        assert!(open_vault(b"password", &salt, &sealed).is_err());
    }
}
