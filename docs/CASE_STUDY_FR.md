# Étude de cas — ConfidIS OS

**Projet personnel open source — Rust, systèmes distribués et stockage chiffré.**  
**État :** projet en développement, sans certification de sécurité ou homologation réglementaire.

## 1. Problème et objectif

Permettre à une organisation de traiter temporairement des données sensibles sur une infrastructure maîtrisée, sans conserver inutilement des versions en clair. ConfidIS est conçu comme une appliance auto-hébergée et une fédération explicite de nœuds de confiance, non comme une place de marché de stockage.

## 2. Architecture retenue

- **Déploiement :** environnement Debian, VM, Proxmox ou serveur dédié.
- **Chiffrement côté client :** séparation entre conservation des fragments et accès aux clés.
- **Reed–Solomon :** fragments de données et de parité selon une politique d’encodage.
- **Placement des fragments :** sélection de nœuds et vérification de diversité des domaines de défaillance.
- **Fédération de confiance :** relations explicites entre opérateurs, avec quotas et politiques.
- **Traçabilité :** conception de reçus et de journaux d’exploitation vérifiables.

**Flux conceptuel :** chiffrement client → fragments → politique de placement → stockage chez des nœuds → restitution / vérification.

[Présentation en français](../README_FR.md) · [Modules Rust](../crates/)

## 3. Réalisation observable

Le dépôt contient des crates Rust pour les protocoles, le chiffrement, le codage à effacement, le placement et les opérations de nœuds, ainsi que des éléments de déploiement et d’interface. Les exemples les plus faciles à auditer sont le [module Reed–Solomon](../crates/confidis-erasure/src/lib.rs) et le [planificateur de placement](../crates/confidis-placement/src/lib.rs).

La présence de ces mécanismes dans le code n’établit pas leur fiabilité sur des nœuds indépendants en situation réelle.

## 4. Choix et compromis

| Décision | Bénéfice recherché | Vérification nécessaire |
| --- | --- | --- |
| Chiffrement en amont du stockage | Confidentialité du contenu | Gestion des clés et menaces réelles |
| Redondance Reed–Solomon | Reconstitution malgré certaines pertes | Campagnes de panne et benchmarks |
| Diversité des nœuds | Réduire les pannes corrélées | Indépendance physique réelle |
| Fédération contractuelle | Confiance définie explicitement | Révocation, incidents et gouvernance |
| Rétention limitée | Réduire l’exposition des données | Efficacité de la suppression |

## 5. Validation et limites

Les objectifs de protection des données s’inscrivent dans une démarche RGPD, NIS2 et recommandations ANSSI, **sans présumer une conformité automatique ni une certification ANSSI**. Les garanties de confidentialité, disponibilité et suppression exigent des essais et audits de déploiement.

## 6. Compétences illustrées

Architecture distribuée, Rust, conception de protocoles, stockage et réplication, modélisation de confiance, risques et documentation technique. Il s’agit d’un projet personnel, pas d’une mission client.

[Retour au dépôt](../README.md)
