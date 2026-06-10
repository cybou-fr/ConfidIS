fn main() {
    println!("cargo:rerun-if-env-changed=CONFIDIS_GENESIS_ROOT_PUBKEY_HEX");
}
