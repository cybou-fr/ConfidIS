#![cfg(target_arch = "wasm32")]

use confidis_crypto_wasm::{
    generate_mnemonic_24, generate_vault_salt_js, is_mnemonic_valid, sign_with_signing_key_hex,
    signing_key_from_mnemonic_js, vault_open, vault_seal, verify_with_verifying_key_hex,
    verifying_key_from_signing_key,
};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn wasm_wallet_can_derive_sign_and_verify() {
    let mnemonic = generate_mnemonic_24().expect("mnemonic");
    assert!(is_mnemonic_valid(&mnemonic));

    let signing_key_hex =
        signing_key_from_mnemonic_js(&mnemonic, "").expect("signing key from mnemonic");
    let verifying_key_hex =
        verifying_key_from_signing_key(&signing_key_hex).expect("verifying key");
    let message = b"confidis wasm wallet contract";
    let signature_hex = sign_with_signing_key_hex(&signing_key_hex, message).expect("signature");

    assert_eq!(signing_key_hex.len(), 64);
    assert_eq!(verifying_key_hex.len(), 64);
    assert_eq!(signature_hex.len(), 128);
    assert!(
        verify_with_verifying_key_hex(&verifying_key_hex, message, &signature_hex)
            .expect("valid signature")
    );
    assert!(
        !verify_with_verifying_key_hex(&verifying_key_hex, b"tampered", &signature_hex)
            .expect("tampered signature returns false")
    );
}

#[wasm_bindgen_test]
fn wasm_vault_seal_open_rejects_wrong_password() {
    let password = b"correct horse battery staple";
    let salt = generate_vault_salt_js();
    let plaintext_key = vec![42u8; 32];

    let ciphertext = vault_seal(password, &salt, &plaintext_key).expect("seal");
    let opened = vault_open(password, &salt, &ciphertext).expect("open");

    assert_ne!(ciphertext, plaintext_key);
    assert_eq!(opened, plaintext_key);
    assert!(vault_open(b"wrong password", &salt, &ciphertext).is_err());
}
