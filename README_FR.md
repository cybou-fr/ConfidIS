<p align="center"><img src="web-ui/public/logo.svg" alt="CONFIDIS" width="120" height="120" /></p>

# ConfidIS OS

**ConfidIS OS est une appliance open-source basée sur Debian pour la création de cellules de données personnelles temporaires chiffrées, la fédération de noeuds de confiance et la production de preuves d'exploitation.**

ConfidIS OS permet à une organisation de déployer son propre noeud de stockage sur son infrastructure : Proxmox, VM, mini-serveur, VPS ou bare metal. Le projet est une solution auto-hébergée "local-first", conçue pour la souveraineté, la confidentialité des données et la conformité (RGPD, NIS2, recommandations ANSSI).

## Concepts Clés

ConfidIS OS n'est pas un cloud de fichiers généraliste, ni un système de sauvegarde permanent, ni une place de marché de stockage publique. Il sert un objectif précis : permettre aux organisations de manipuler des données personnelles sensibles sans devenir inutilement le détenteur permanent de ces données en clair.

*   **Cellules de données temporaires et chiffrées :** Les données sont chiffrées côté client avec une clé détenue uniquement par le propriétaire, découpées via le codage à effacement Reed-Solomon et réparties sur des noeuds de stockage indépendants. Aucun noeud ni opérateur ne peut lire les données.
*   **Zero-Knowledge :** Les noeuds ne stockent que des fragments chiffrés et des hachages BLAKE3. Ils n'ont pas accès au texte en clair, aux noms de fichiers ou aux clés de déchiffrement.
*   **Fédération de noeuds de confiance :** La fédération repose sur des accords explicites entre noeuds. Chaque noeud configure ses partenaires, ses points de terminaison et ses limites d'usage mutuelles.
*   **Preuves d'exploitation :** Le système produit des pistes d'audit, des reçus signés pour le stockage et la suppression, ainsi que des rapports de préparation (readiness) pour les audits de conformité.

---

## Alignement Conformité

ConfidIS OS est conçu pour soutenir des déploiements alignés avec les recommandations **RGPD, NIS2 et ANSSI** :
- Privacy by design et par défaut.
- Chiffrement côté client.
- Limites strictes de rétention des données.
- Fédération de confiance.
- Séparation des surfaces utilisateur/opérateur.
- Packs de preuves d'audit exportables.

*Note : Le projet ne revendique aucune certification ANSSI ou qualification réglementaire spécifique. L'audit de conformité et la validation du déploiement restent de la responsabilité de l'organisation.*

---

## Modèle Technique

ConfidIS OS fonctionne sans jetons, crédits internes, économie crypto ou places de marché de stockage publiques. L'utilisation est régulée par :
- Des quotas locaux par noeud.
- Des plans de service.
- Des politiques d'organisation.
- Des accords de fédération explicites.
- Des reçus d'utilisation signés et des journaux d'audit.

---

## Démarrage

### Prérequis
- Environnement basé sur Debian (Proxmox, VM, ou bare metal).
- Accès administratif pour l'installation.

### Options de déploiement
- **Proxmox :** Utilisez l'image QCOW2.
- **Bare Metal :** Utilisez l'image ISO pour les serveurs dédiés.
- **Docker (Développement/Démonstration) :** Utilisez les configurations Docker fournies.
- **Debian :** Installez via les scripts de packaging Debian fournis.

Pour des instructions de configuration détaillées, consultez le répertoire `deploy/`.

---

## Contribution

Nous accueillons les contributions à ConfidIS OS. Veuillez consulter nos directives de contribution (à venir) pour plus d'informations.

---

## Support & Dons

ConfidIS OS est un projet open-source maintenu par la communauté et soutenu par des services professionnels. Si vous trouvez de la valeur dans ce projet, merci d'envisager de soutenir son développement et sa durabilité à long terme :

*   **Contribuer au code :** Consultez nos issues ouvertes et soumettez des pull requests.
*   **Signaler des problèmes :** Aidez-nous à améliorer la stabilité en signalant les bugs.
*   **Sponsoring :** Si vous êtes une organisation utilisant ConfidIS OS, envisagez de parrainer notre développement ou de solliciter nos services professionnels (installation, formation, support, assistance aux audits).

Pour les demandes de dons ou de sponsoring, veuillez nous contacter à ioustamora@gmail.com. Votre soutien aide à maintenir ConfidIS OS sécurisé, conforme et gratuit pour tous.

---

## Licence

Ce projet est sous licence [Apache License, Version 2.0](LICENSE).
