# Interface web CONFIDIS

L’interface web est l’expérience CONFIDIS hébergée par le noeud, destinée aux visiteurs, utilisateurs finaux, opérateurs et administrateurs. Elle est construite comme un bundle statique Vite/React et servie par le déploiement du noeud via `webui_path` et, au besoin, `content_dir`.

## Surfaces requises

Tout noeud de production doit livrer :

- Page d’accueil marketing : explique CONFIDIS, la propriété, les limites zero-knowledge et le contact/onboarding en termes simples.
- Docs utilisateur final : création de wallet, création de la première Cellule, sauvegarde de la mnémonique, perte de clé, renouvellement, suppression, création/retrait de copies chiffrées pour destinataire, et partage sûr sans export brut de la clé de Cellule.
- Docs opérateur : état du noeud, support d’onboarding orienté wallet, provisionnement CYB, packages destinataire reçus, preuves d’audit, avertissements de maintenance et flux de support.
- Docs admin : installation/mise à niveau, identité de noeud zéro-config, découverte de pairs `/peers`, gouvernance réactive de l’autorité CONFIDIS, profil de production, sauvegardes, supervision, réponse aux incidents et rollback.
- Routes applicatives authentifiées : tableau de bord, coffre, opérateur, wallet, copies partagées et vues de santé des données.

## Règles de sécurité

- Aucune page publique ne doit exposer de clés privées, de texte en clair, de clés de Cellule brutes, de manifestes, de placement de shards de données utilisateur, de reçus, d’inventaires de packages ou de preuves réservées à l’opérateur.
- Les pages qui montrent des preuves locales du noeud doivent utiliser l’authentification UI.
- Les pages qui montrent des rapports de placement ou de cycle de vie spécifiques au propriétaire doivent exiger une authentification par signature du propriétaire.
- Le contenu marketing/docs public doit éviter les scripts tiers, l’analytique, les polices externes et les pixels de suivi.
- La sortie de build doit préserver les protections CSP et SRI.

## Build

```bash
npm install
npm run build
```

`npm run build` exécute Vite puis injecte les empreintes SRI dans `dist/index.html`.

## Développement

```bash
npm run dev
npm run lint
```

La configuration de lint est volontairement stricte car le wallet navigateur est critique pour la sécurité.
