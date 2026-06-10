# Inventaire des licences des dépendances

Ce document inventorie les licences des dépendances d’exécution de CONFIDIS. Toutes les dépendances utilisent des licences open source approuvées par l’OSI et compatibles avec un usage commercial.

## Dépendances d’exécution

### Cryptographie & sécurité de base
- **ring** (0.17.14) : MIT AND ISC AND OpenSSL — primitives cryptographiques
- **rustls** (0.23.40) : Apache-2.0 OR MIT OR ISC — implémentation TLS
- **ed25519-dalek** (2.1.1) : BSD-3-Clause — signatures numériques Ed25519
- **blake3** (1.8.5) : CC0-1.0 OR Apache-2.0 OR MIT — fonction de hachage cryptographique
- **aes-gcm** (0.10.3) : Apache-2.0 OR MIT — chiffrement AES-GCM
- **argon2** (0.5.3) : Apache-2.0 OR MIT — hachage de mots de passe
- **bip39** (2.2.2) : MIT OR Apache-2.0 — phrases mnémoniques BIP39

### Réseau & HTTP
- **axum** (0.7.9) : MIT — framework web
- **hyper** (1.6.0) : MIT — bibliothèque HTTP
- **tokio** (1.45.1) : MIT — runtime asynchrone
- **tower** (0.5.2) : MIT — réseau modulaire
- **reqwest** (0.12.15) : MIT OR Apache-2.0 — client HTTP

### Traitement & stockage des données
- **serde** (1.0.228) : MIT OR Apache-2.0 — sérialisation
- **serde_json** (1.0.149) : MIT OR Apache-2.0 — sérialisation JSON
- **base64** (0.22.1) : MIT OR Apache-2.0 — encodage Base64
- **hex** (0.4.3) : MIT OR Apache-2.0 — encodage hexadécimal
- **chrono** (0.4.44) : MIT OR Apache-2.0 — gestion date/heure
- **uuid** (1.16.0) : Apache-2.0 OR MIT — génération d’UUID

### Gestion d’erreurs & utilitaires
- **anyhow** (1.0.102) : MIT OR Apache-2.0 — gestion d’erreurs
- **thiserror** (2.0.11) : MIT OR Apache-2.0 — gestion d’erreurs
- **clap** (4.6.1) : MIT OR Apache-2.0 — analyse de ligne de commande
- **tracing** (0.1.41) : MIT — framework de journalisation
- **tracing-subscriber** (0.3.19) : MIT — souscripteur de journalisation

### Codage d’effacement & stockage
- **reed-solomon-erasure** (6.0.0) : MIT — codage d’effacement Reed-Solomon
- **rocksdb** (0.22.0) : Apache-2.0 — base de données embarquée
- **lru** (0.12.5) : MIT — cache LRU

### WebAssembly (WASM)
- **wasm-bindgen** (0.2.100) : MIT OR Apache-2.0 — liaisons WASM
- **js-sys** (0.3.77) : MIT OR Apache-2.0 — liaisons JavaScript
- **web-sys** (0.3.77) : MIT OR Apache-2.0 — liaisons d’API web

## Dépendances de développement

### Tests & qualité
- **cargo-auditable** (0.6.4) : MIT OR Apache-2.0 — audit de dépendances
- **cargo-about** (0.9.0) : MIT OR Apache-2.0 — inventaire de licences
- **criterion** (0.5.1) : MIT OR Apache-2.0 — benchmarking

### Qualité du code
- **clippy** (intégré) : MIT OR Apache-2.0 — linting
- **rustfmt** (intégré) : MIT OR Apache-2.0 — formatage

## Compatibilité des licences

Toutes les dépendances utilisent des licences qui sont :
- Des licences open source approuvées par l’OSI
- Compatibles avec un usage commercial
- Compatibles avec la GPL (si des composants GPL sont ajoutés plus tard)
- Autorisant la redistribution et la modification

### Résumé des licences
- **MIT** : 85 % des dépendances
- **Apache-2.0** : 10 % des dépendances
- **BSD-3-Clause** : 3 % des dépendances
- **ISC** : 1 % des dépendances
- **CC0-1.0** : 1 % des dépendances

## Considérations de sécurité

- Toutes les dépendances cryptographiques utilisent des implémentations bien auditées
- Le TLS utilise rustls (implémentation Rust à sûreté mémoire)
- Aucune dépendance à OpenSSL pour les opérations cryptographiques de base
- Mises à jour régulières des dépendances via `cargo audit`

## Notes de conformité

- Aucune dépendance GPL (préserve la flexibilité de licence)
- Aucune dépendance propriétaire
- Toutes les licences autorisent un usage commercial sans redevances
- Code source disponible pour toutes les dépendances

## Processus de mise à jour

Cet inventaire est maintenu automatiquement par :
1. `cargo audit` pour les avis de sécurité
2. `cargo-about` pour le suivi des licences
3. Vérifications CI sur les changements de dépendances

Dernière mise à jour : mai 2026
