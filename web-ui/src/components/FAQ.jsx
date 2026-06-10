import { useState } from 'react';
import { HelpCircle, ChevronDown, ChevronUp } from 'lucide-react';

const faqs = [
  {
    audience: "user",
    q: "Qu’est-ce qu’une Cellule ?",
    a: "Une Cellule est votre espace de données personnel chiffré sur le réseau CONFIDIS. Lorsque vous téléversez un fichier, il est chiffré côté client avec une clé que vous seul détenez, découpé en shards Reed-Solomon (20 données + 10 parité) et réparti sur des noeuds de stockage indépendants. Aucun noeud ni opérateur ne peut lire vos données. Une Cellule possède une date d’expiration choisie par le propriétaire, après laquelle tous les shards sont supprimés automatiquement."
  },
  {
    audience: "user",
    q: "Qu’est-ce que le stockage zero-knowledge ?",
    a: "Le zero-knowledge signifie que les noeuds CONFIDIS ne stockent que des shards chiffrés opaques — ils ne voient jamais vos données en clair, vos noms de fichiers ni vos clés de déchiffrement. Même si tous les noeuds du réseau étaient compromis simultanément, un attaquant n’obtiendrait que des fragments chiffrés. Le déchiffrement n’a lieu que côté client, avec la clé de Cellule que vous avez générée."
  },
  {
    audience: "user",
    q: "Que se passe-t-il si je perds ma clé privée ?",
    a: "Par conception, une clé perdue signifie un accès perdu. CONFIDIS ne propose ni récupération de clé, ni séquestre, ni porte dérobée. C’est intentionnel : tout mécanisme de récupération impliquerait de stocker votre clé quelque part, ce qui affaiblirait la garantie zero-knowledge. Si vous perdez votre clé, créez une nouvelle Cellule et téléversez de nouveau vos données. L’ancienne Cellule sera supprimée automatiquement à l’échéance de son expiration."
  },
  {
    audience: "user",
    q: "CONFIDIS ou les opérateurs de noeuds peuvent-ils lire mes fichiers ?",
    a: "Non. Chaque fichier est chiffré avec ChaCha20-Poly1305 avant de quitter votre appareil. Le texte chiffré obtenu est ensuite découpé en shards avant stockage. Les noeuds ne reçoivent que des octets de shards chiffrés et un hachage BLAKE3 — ils n’ont aucun accès à la clé de Cellule, au manifeste, ni à aucune métadonnée permettant d’identifier votre fichier."
  },
  {
    audience: "user",
    q: "Qui contrôle l’accès à mes données ?",
    a: "Le propriétaire de la Cellule contrôle l’accès. Votre clé privée Ed25519 contrôle les enregistrements de Cellule, le renouvellement, la suppression, les décisions de packages destinataire et les rapports authentifiés par le propriétaire. Une organisation ne peut recevoir qu’un accès en lecture seule aux copies chiffrées que vous créez pour son identité/sa clé publique. Cette organisation ne peut pas supprimer ou renouveler vos Cellules, consulter des rapports complets de propriétaire, ni accéder à quoi que ce soit hors de ce package."
  },
  {
    audience: "user",
    q: "Que se passe-t-il quand je crée une Cellule chez une organisation ?",
    a: "L’organisation fournit le matériel, la capacité de stockage, la connectivité internet, l’électricité, les quotas locaux et une identité destinataire à clé publique. Vous restez le propriétaire unique de la Cellule : votre clé privée Ed25519 est la seule à pouvoir signer création, mise à jour, partage et suppression. L’organisation peut recevoir un accès en lecture seule uniquement via un package destinataire que vous lui créez explicitement."
  },
  {
    audience: "user",
    q: "Puis-je gérer mes données sans dépendre de l’organisation qui les héberge ?",
    a: "Oui. Votre clé propriétaire reste l’autorité cryptographique sur les Cellules : lecture, partage, renouvellement et suppression passent par des signatures propriétaire. Une organisation ne peut pas recevoir plus que les packages destinataire que vous créez explicitement."
  },
  {
    audience: "user",
    q: "Puis-je partager des données avec une autre organisation plus tard ?",
    a: "Oui. Le modèle de production est un package destinataire signé par le propriétaire pour l’identité/la clé publique d’une autre organisation. Le package lie la Cellule, la clé publique du destinataire, le périmètre de champs/données, le statut, l’expiration et votre signature de propriétaire. Le destinataire prouve la possession de sa clé privée avant la livraison. Retirer ou faire expirer le package interrompt toute livraison future médiée par CONFIDIS."
  },
  {
    audience: "user",
    q: "Un noeud peut-il me montrer où tous mes shards sont stockés ?",
    a: "Un noeud local ne peut montrer que sa propre santé, l’état de la liste de quarantaine de l’autorité, sa vue des pairs, sa capacité et les shards chiffrés qu’il stocke localement. Un rapport de placement complet par Cellule exige une authentification du propriétaire par signature, car seul le contexte de manifeste côté propriétaire peut révéler en toute sécurité la carte complète des shards de ces données."
  },
  {
    audience: "both",
    q: "Comment l’usage est-il limité ?",
    a: "Chaque noeud applique des quotas locaux : nombre d’utilisateurs, nombre de Cellules, stockage total, taille maximale de fichier, durée maximale et réserve d’espace disque. En fédération, chaque peer a aussi des limites inbound/outbound et peut être suspendu si l’accord est dépassé."
  },
  {
    audience: "both",
    q: "Comment la suppression de mes données est-elle garantie ?",
    a: "Chaque Cellule possède un horodatage d’expiration choisi par le propriétaire. À cette échéance, le worker de suppression local de chaque noeud supprime automatiquement le shard et émet un reçu de suppression signé. Vous pouvez aussi déclencher une suppression explicite avec « confidis cellule delete », qui envoie une demande de suppression signée à chaque noeud détenant un shard. Les reçus de suppression sont signés Ed25519 et vérifiables de manière indépendante."
  },
  {
    audience: "both",
    q: "Comment CONFIDIS se conforme-t-il au RGPD et à NIS2 ?",
    a: "CONFIDIS est conçu pour aider les organisations françaises et européennes à réduire la charge opérationnelle RGPD : protection de la vie privée dès la conception, chiffrement côté client, preuves de placement en région UE, expiration explicite et reçus de suppression signés. Le rôle exact de responsable/sous-traitant et les obligations NIS2 dépendent encore du déploiement et doivent être validés avec le conseil juridique ou le DPO de l’organisation."
  },
  {
    audience: "user",
    q: "Comment partager l’accès à une Cellule avec quelqu’un d’autre ?",
    a: "Utilisez le flux « Copies partagées » du wallet pour créer un package chiffré pour la clé publique du destinataire. Le parcours de production est le partage par package, car il garde explicites le périmètre, l’expiration, le retrait et les preuves d’audit."
  },
  {
    audience: "user",
    q: "Puis-je révoquer l’accès après un partage ?",
    a: "Oui pour les packages destinataire : retirez ou faites expirer le package pour interrompre la livraison médiée par CONFIDIS de cette copie chiffrée. Le retrait ne peut pas techniquement récupérer un texte en clair qu’un lecteur autorisé a déjà consulté ou exporté."
  },
  {
    audience: "user",
    q: "Que se passe-t-il quand une Cellule est sur le point d’expirer ?",
    a: "La commande CLI « confidis cellule expiry-check --registry ./registry.json --days 30 » liste toutes les Cellules expirant sous 30 jours. Les Cellules entrent dans l’état « ExpiringSoon » 30 jours avant leur expiration. Le propriétaire peut prolonger une Cellule active à tout moment, mais la nouvelle expiration doit être au plus à un an de la date de renouvellement. Le renouvellement doit avoir lieu avant l’expiration — une Cellule expirée ne peut pas être renouvelée."
  },
  {
    audience: "both",
    q: "Une organisation doit-elle télécharger mes données en local ?",
    a: "CONFIDIS encourage les organisations à conserver les données utilisateur dans CONFIDIS et à y accéder via le client ou l’API CONFIDIS, y compris pour les intégrations CRM ou d’automatisation. Si une organisation a une permission de lecture, elle peut rester techniquement capable d’enregistrer du texte en clair localement ; CONFIDIS ne peut pas l’empêcher totalement. Le produit doit rappeler aux lecteurs d’éviter les copies locales en clair et de conserver une piste d’audit via l’accès CONFIDIS."
  },
  {
    audience: "both",
    q: "Qu’est-ce que le codage d’effacement Reed-Solomon 20+10 ?",
    a: "Vos données chiffrées sont découpées en 20 shards de données et 10 shards de parité (30 au total). 20 shards quelconques parmi les 30 suffisent à reconstruire les données d’origine. Jusqu’à 10 pannes de noeuds ou pertes de shards simultanées sont donc tolérées sans aucune perte de données. En production, les 30 shards sont répartis sur 30 noeuds et domaines de panne indépendants pour maximiser la résilience."
  },
  {
    audience: "operator",
    q: "Comment exploiter un noeud de stockage CONFIDIS ?",
    a: "Installez l’appliance ou le paquet Debian, configurez l’identité du noeud, le stockage, les quotas, les packages destinataire, les pairs de fédération et la console opérateur locale. La santé courante, l’expiration, l’intégrité, la journalisation, la réparation et les preuves doivent s’exécuter automatiquement."
  },
  {
    audience: "operator",
    q: "Comment savoir qu’un noeud est prêt ?",
    a: "Pour la préparation à la production, le noeud doit disposer d’une identité locale, d’une surface opérateur non publique, d’un endpoint public contrôlé, d’une politique de transport sécurisée, de quotas, d’une surface web embarquée, de backups vérifiés et d’un rapport de readiness clair."
  },
  {
    audience: "operator",
    q: "Où voir les données partagées avec mon organisation ?",
    a: "Sur une console locale/non-production, déverrouillez le wallet opérateur sur la page Noeud : le panneau liste seulement les métadonnées des packages destinataire actifs adressés à cette clé publique. En production publique, cet inventaire est désactivé jusqu’à une authentification opérateur signée. Le contenu reste chiffré et doit être ouvert par le flux d’accès avec preuve de la clé destinataire."
  },
  {
    audience: "both",
    q: "Puis-je vérifier que mes données sont intactes ?",
    a: "Oui. Chaque noeud exécute périodiquement un vérificateur d’intégrité BLAKE3 et la Santé des données résume les preuves locales de shards, la capacité du noeud, les pairs et l’état d’expiration. Des rapports de disponibilité authentifiés par le propriétaire permettent de vérifier quels shards sont présents, manquants ou corrompus sur le réseau. Si des shards manquent, le flux de réparation les reconstruit à partir de pairs sains et téléverse des remplacements."
  },
  {
    audience: "operator",
    q: "Et si je veux déplacer mes données vers d’autres noeuds ?",
    a: "Le rééquilibrage est prévu pour s’exécuter comme une tâche de noeud en arrière-plan par défaut lorsque des noeuds deviennent pleins, en mauvaise santé ou indisponibles. Les commandes CLI expertes telles que « confidis cellule rebalance-plan » et « confidis cellule rebalance » restent disponibles pour les flux d’audit et de récupération, mais l’expérience produit normale ne doit pas exiger de mémoriser des commandes de maintenance."
  },
];

function FAQItem({ item }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      style={{
        borderRadius: '12px',
        border: '1px solid var(--border-color)',
        background: open ? 'rgba(69,243,255,0.03)' : 'rgba(255,255,255,0.02)',
        transition: 'var(--transition)',
        overflow: 'hidden',
      }}
    >
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: '100%',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1.25rem 1.5rem',
          background: 'transparent',
          border: 'none',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          textAlign: 'left',
          gap: '1rem',
        }}
      >
        <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>{item.q}</span>
        {open
          ? <ChevronUp size={18} color="var(--accent-primary)" style={{ flexShrink: 0 }} />
          : <ChevronDown size={18} color="var(--text-secondary)" style={{ flexShrink: 0 }} />}
      </button>
      {open && (
        <div style={{ padding: '0 1.5rem 1.25rem', color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.7 }}>
          {item.a}
        </div>
      )}
    </div>
  );
}

// `audience` selects which questions to show: 'user' (default) or 'operator'.
// Entries tagged 'both' appear in either view.
export default function FAQ({ audience = 'user' }) {
  const visible = faqs.filter(
    (f) => f.audience === audience || f.audience === 'both',
  );
  const isOperator = audience === 'operator';
  return (
    <div style={{ padding: '2rem', maxWidth: '860px' }}>
      <header style={{ marginBottom: '2.5rem' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <HelpCircle color="var(--accent-primary)" />{' '}
          {isOperator ? 'FAQ opérateur' : 'FAQ utilisateur'}
        </h1>
        <p style={{ color: 'var(--text-secondary)' }}>
          {isOperator
            ? 'Exploiter un noeud CONFIDIS : gouvernance, intégrité, réparation, rééquilibrage, données partagées et exploitation quotidienne.'
            : "Vos données, vos clés, la confidentialité, le partage, les quotas et la suppression — en termes simples."}
        </p>
      </header>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {visible.map((item, i) => (
          <FAQItem key={i} item={item} />
        ))}
      </div>
    </div>
  );
}
