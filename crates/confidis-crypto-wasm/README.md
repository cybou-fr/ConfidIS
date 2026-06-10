# confidis-crypto-wasm

Liaisons WebAssembly pour [`confidis-crypto`](../confidis-crypto). Utilisées par le wallet navigateur pour générer des clés, signer des charges utiles de protocole et sceller/ouvrir le coffre protégé par mot de passe — le tout dans le navigateur de l’utilisateur, sans jamais envoyer de matériel de clé au serveur.

Ce crate est **uniquement** un wrapper `wasm-bindgen`. Toute la logique cryptographique réside dans `confidis-crypto` et est partagée par le noeud, la CLI et le wallet, garantissant une disposition d’octets et une vérification de signature identiques sur toutes les surfaces.

## API JavaScript exposée

| Fonction JS | Rôle |
|---|---|
| `defaultArgon2MemoryKib()` / `defaultArgon2Iterations()` / `defaultArgon2Parallelism()` / `defaultArgon2OutputLen()` | Constantes en lecture seule des paramètres Argon2id de production calibrés (m=64 Mio, t=3, p=1, sortie 32 octets). |
| `generateMnemonic24()` | Génère une nouvelle mnémonique BIP39 de 24 mots en anglais. |
| `isMnemonicValid(mnemonic)` | Valide une mnémonique BIP39 (liste de mots + somme de contrôle). |
| `signingKeyFromMnemonic(mnemonic, passphrase)` | Dérive de façon déterministe la clé de signature Ed25519 encodée en hex. **Worker uniquement** : le hex retourné contient la clé privée. |
| `verifyingKeyFromSigningKey(signingKeyHex)` | Dérive la clé publique encodée en hex. Peut être transmise au thread principal sans risque. |
| `signWithSigningKey(signingKeyHex, messageBytes)` | Produit une signature Ed25519 encodée en hex. Entrée réservée au Worker. |
| `verifyWithVerifyingKey(verifyingKeyHex, messageBytes, signatureHex)` | Vérifie une signature. Renvoie `true` uniquement en cas de succès. |
| `argon2idDerive(password, salt, mKib, t, p, outLen)` | KDF Argon2id brut pour les appelants avancés. |
| `generateVaultSalt()` | Nouveau sel de 16 octets pour le scellement du coffre. |
| `vaultSeal(password, salt, plaintext)` | Dérive une clé d’Argon2id depuis `(password, salt)`, puis scelle `plaintext` avec ChaCha20-Poly1305. |
| `vaultOpen(password, salt, ciphertext)` | Inverse de `vaultSeal`. Erreur opaque en cas de mauvais mot de passe / texte chiffré altéré. |
| `bytesToHex(bytes)` / `hexToBytes(hex)` | Utilitaires hex pour garder le code JS compact. |

L’API complète est définie dans [`src/lib.rs`](./src/lib.rs).

## Contrat de modèle de menace appliqué par les liaisons

Le module wasm est prévu pour s’exécuter **dans un Web Worker** lancé par le wallet `web-ui`, et non directement sur le thread principal. La répartition est :

- Thread principal → envoie `{ session_handle, payload_bytes }` au Worker.
- Worker → détient la clé de signature déverrouillée, appelle `signWithSigningKey`, renvoie `{ signature_hex }`.
- Le hex de la clé de signature ne revient jamais au thread principal.

Le `.wasm` compilé doit être chargé avec l’attribut `integrity=` (SRI) dans `index.html` et servi depuis la même origine que l’UI du wallet. La CSP de la route wallet interdit les scripts inline, les origines tierces et `eval`, ce qui réduit le risque résiduel.

## Compilation

### Prérequis

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --locked
```

`wasm-pack` est l’outil standard pour empaqueter des artefacts Rust-WASM destinés aux consommateurs JavaScript. Il exécute `cargo build --release --target wasm32-unknown-unknown`, post-traite avec `wasm-bindgen-cli`, puis optimise avec `wasm-opt`. Résultat : un paquet compatible npm avec `.wasm`, le glue `.js` et les déclarations de types `.d.ts`.

### Build pour le bundler web-ui

Depuis la racine du workspace :

```sh
wasm-pack build crates/confidis-crypto-wasm \
  --release \
  --target bundler \
  --out-dir ../../web-ui/wasm/confidis-crypto-wasm
```

Structure de sortie (consommée par Vite) :

```
web-ui/wasm/confidis-crypto-wasm/
├── confidis_crypto_wasm_bg.wasm        # binaire optimisé (~150–250 Ko gzip)
├── confidis_crypto_wasm_bg.wasm.d.ts
├── confidis_crypto_wasm.d.ts           # types TypeScript pour chaque fonction exportée
├── confidis_crypto_wasm.js             # glue JS
└── package.json
```

Le web-ui l’importe ainsi :

```ts
import init, {
  generateMnemonic24,
  signingKeyFromMnemonic,
  vaultSeal,
  vaultOpen,
  signWithSigningKey,
} from "confidis-crypto-wasm";

await init(); // charge et instancie le .wasm
const mnemonic = generateMnemonic24();
// …
```

### Vérification de compilation native (hôte)

Le crate se compile et se teste aussi sur la cible hôte afin que les smoke-tests `cargo build` / `cargo test` du workspace le couvrent :

```sh
cargo test -p confidis-crypto-wasm
```

Sur une cible non wasm32, la surface d’API `#[wasm_bindgen]` est masquée derrière une barrière `#[cfg(target_arch = "wasm32")]`. Un `native_smoke_test` minimal confirme que les symboles `confidis-crypto` sous-jacents se résolvent toujours. La logique réellement exposée à JS n’est atteignable qu’après exécution de `wasm-pack`.

### Tests navigateur

Les tests WASM côté navigateur sont exécutés via [`wasm-bindgen-test`](https://rustwasm.github.io/wasm-bindgen/wasm-bindgen-test/). `tests/browser.rs` couvre le contrat critique du wallet : génération de mnémonique, dérivation de clé, signature/vérification et scellement/ouverture du coffre.

```sh
wasm-pack test --node crates/confidis-crypto-wasm
node ./scripts/test-wasm-browser.mjs
wasm-pack test --headless --chrome crates/confidis-crypto-wasm
```

Le lanceur Firefox du depot conserve le resultat de `wasm-pack`, puis ferme
proprement l'arbre navigateur si Firefox reste actif apres un resultat reussi.

## Ce que ce crate n’expose *pas*

Par conception :

- Pas de `derive_manifest_key` / `seal_cellule_key` / scellement X25519 — ce sont des préoccupations opérateur côté serveur, pas des préoccupations du wallet.
- Aucun accès au système de fichiers ni au réseau, d’aucune sorte. Le Worker qui héberge ce module est purement computationnel.
- Aucune source d’aléa au-delà de `crypto.getRandomValues` (via la fonctionnalité `js` du crate `getrandom`). Le wallet doit s’exécuter dans un contexte sécurisé (HTTPS ou `localhost`).

## Versionnage

Tout ce qui modifie la disposition d’octets d’un coffre scellé, le tag de dérivation de `signingKeyFromMnemonic`, ou les paramètres Argon2id par défaut est un **changement cassant** qui invalide chaque wallet existant. De tels changements doivent :

- incrémenter la version du crate,
- mettre à jour `WALLET_ED25519_DERIVATION_TAG` dans `confidis-crypto`,
- livrer une procédure de migration documentée pour les détenteurs de wallets existants.

Voir `ROADMAP_CONFIDIS_OS.md` § Wallet navigateur pour la politique complète de gestion des versions.
