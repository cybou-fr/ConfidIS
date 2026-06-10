import { useState } from 'react';
import { BookOpen, Key, Upload, Download, Share2, RefreshCw, Trash2, Shield, Activity } from 'lucide-react';

const S = {
  page: { padding: '2rem', maxWidth: '900px' },
  h1: { fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' },
  h2: { fontSize: '1.35rem', fontWeight: 700, margin: '2.5rem 0 1rem', display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--text-primary)' },
  h3: { fontSize: '1.05rem', fontWeight: 600, margin: '1.5rem 0 0.5rem', color: 'var(--accent-primary)' },
  p: { color: 'var(--text-secondary)', lineHeight: 1.75, marginBottom: '0.75rem', fontSize: '0.925rem' },
  code: {
    display: 'block', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border-color)',
    borderRadius: '10px', padding: '1rem 1.25rem', fontFamily: 'monospace',
    fontSize: '0.825rem', color: '#a5f3fc', marginBottom: '1rem', overflowX: 'auto',
    lineHeight: 1.6,
  },
  inlineCode: { fontFamily: 'monospace', color: 'var(--accent-primary)', background: 'rgba(69,243,255,0.08)', padding: '0.1em 0.4em', borderRadius: '4px', fontSize: '0.875em' },
  note: { background: 'rgba(168,85,247,0.06)', border: '1px solid rgba(168,85,247,0.2)', borderRadius: '10px', padding: '1rem 1.25rem', fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' },
  warn: { background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.2)', borderRadius: '10px', padding: '1rem 1.25rem', fontSize: '0.875rem', color: '#f9a8d4', marginBottom: '1rem' },
  divider: { borderTop: '1px solid var(--border-color)', margin: '2.5rem 0' },
};

function Code({ children }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ position: 'relative' }}>
      <pre style={S.code}>{children}</pre>
      <button
        onClick={() => { navigator.clipboard.writeText(children); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        style={{ position: 'absolute', top: '0.75rem', right: '0.75rem', background: 'rgba(255,255,255,0.06)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
      >
        {copied ? '✓ copié' : 'copier'}
      </button>
    </div>
  );
}

const sections = [
  {
    id: 'intro', icon: <BookOpen size={20} />, label: 'Introduction',
  },
  { id: 'wallet', icon: <Key size={20} />, label: 'Identité propriétaire' },
  { id: 'cellule-create', icon: <Upload size={20} />, label: 'Créer une Cellule' },
  { id: 'cellule-get', icon: <Download size={20} />, label: 'Récupérer des données' },
  { id: 'sharing', icon: <Share2 size={20} />, label: 'Partager l’accès' },
  { id: 'access-control', icon: <Shield size={20} />, label: 'Contrôle d’accès' },
  { id: 'data-health', icon: <Activity size={20} />, label: 'Santé des données' },
  { id: 'renew', icon: <RefreshCw size={20} />, label: 'Renouvellement' },
  { id: 'delete', icon: <Trash2 size={20} />, label: 'Suppression' },
  { id: 'security', icon: <Shield size={20} />, label: 'Sécurité des clés' },
];

export default function DocsUser() {
  const [active, setActive] = useState('intro');
  const scrollTo = (id) => { setActive(id); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); };

  return (
    <div style={{ display: 'flex', gap: '2rem', padding: '2rem' }}>
      {/* Sidebar TOC */}
      <aside style={{ width: '200px', flexShrink: 0, position: 'sticky', top: '2rem', alignSelf: 'flex-start' }}>
        <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.75rem', fontWeight: 600 }}>Sur cette page</p>
        {sections.map(s => (
          <button key={s.id} onClick={() => scrollTo(s.id)}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', width: '100%', background: 'transparent', border: 'none', padding: '0.4rem 0.5rem', borderRadius: '6px', color: active === s.id ? 'var(--accent-primary)' : 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.8rem', textAlign: 'left', marginBottom: '0.1rem' }}>
            {s.icon}{s.label}
          </button>
        ))}
      </aside>

      {/* Content */}
      <div style={{ flex: 1, maxWidth: '700px' }}>
        <header style={{ marginBottom: '2.5rem' }}>
          <h1 style={S.h1}><BookOpen color="var(--accent-primary)" /> Documentation utilisateur</h1>
          <p style={S.p}>Guide complet pour créer une Cellule temporaire chiffrée, déléguer l’accès et gérer vos preuves avec CONFIDIS OS.</p>
        </header>

        {/* Introduction */}
        <section id="intro">
          <h2 style={S.h2}><BookOpen size={18} color="var(--accent-primary)" /> Introduction</h2>
          <p style={S.p}>CONFIDIS OS est une appliance self-hosted pour des Cellules temporaires chiffrées. Vos fichiers sont chiffrés sur votre appareil avant d’être téléversés. Les noeuds ne reçoivent jamais vos clés ni votre texte en clair — ils ne maintiennent disponibles que des fragments chiffrés opaques pendant la durée active.</p>
          <p style={S.p}>Le concept central est la <strong>Cellule</strong> : une copie numérique temporaire chiffrée de données dont vous gardez l’original hors réseau, avec une date d’expiration choisie par vous. À l’échéance, tous les fragments sont supprimés automatiquement sur chaque noeud qui les détient, produisant des reçus de suppression vérifiables.</p>
          <p style={S.p}>Le produit est autonome par défaut. Les contrôles d’intégrité, la suppression à l’expiration, les scans de réparation, le rééquilibrage, l’évaluation de capacité, les quotas locaux, la fédération de noeuds de confiance et le nettoyage des sessions sécurisées sont des tâches de noeud en arrière-plan ; les petits opérateurs ne devraient pas avoir à mémoriser des commandes de maintenance pour un fonctionnement normal.</p>
          <div style={S.note}>
            <strong>Garantie zero-knowledge :</strong> CONFIDIS n’a jamais votre clé privée. Si vous la perdez, l’accès à cette Cellule réseau est perdu — par conception — mais vos originaux hors réseau restent à vous. Vous pouvez recréer une nouvelle Cellule depuis ces originaux. Sauvegardez votre clé avant de créer votre première Cellule.
          </div>
          <p style={S.p}>Si vous exploitez votre propre noeud, le démarrage le plus simple tient en une seule commande — <span style={S.inlineCode}>confidis</span> (ou <span style={S.inlineCode}>confidis up</span>). Elle configure un noeud d’entreprise et ouvre l’interface web sur <span style={S.inlineCode}>http://127.0.0.1:4433/ui/</span> au premier lancement, puis réutilise cette configuration ensuite. Voir la documentation Admin pour les détails.</p>
        </section>

        <div style={S.divider} />

        {/* Owner identity */}
        <section id="wallet">
          <h2 style={S.h2}><Key size={18} color="var(--accent-primary)" /> Identité propriétaire</h2>

          <div style={S.warn}>
            <strong>Pas de jeton ni de crédit interne dans CONFIDIS OS v1.</strong> Le noeud applique des quotas locaux, une durée maximale de 365 jours et, si la fédération est activée, des accords explicites entre noeuds de confiance.
          </div>

          <h3 style={S.h3}>Générer une paire de clés</h3>
          <p style={S.p}>Votre paire de clés Ed25519 est votre identité propriétaire. La clé privée signe les créations, renouvellements, suppressions, packages destinataire et rapports complets.</p>
          <Code>confidis init-key</Code>
          <p style={S.p}>Cette commande affiche votre clé privée (hex) et votre clé publique (hex). Conservez la clé privée hors ligne et en sécurité.</p>

          <h3 style={S.h3}>Créer un fichier d’identité local</h3>
          <Code>confidis wallet create --public-key &lt;hex-public-key&gt; --output ./wallet.json</Code>
        </section>

        <div style={S.divider} />

        {/* Creating a Cellule */}
        <section id="cellule-create">
          <h2 style={S.h2}><Upload size={18} color="var(--accent-primary)" /> Créer une Cellule</h2>
          <p style={S.p}>La commande <span style={S.inlineCode}>cellule put</span> chiffre, encode et distribue une copie réseau temporaire de votre fichier sur les noeuds en une seule étape. Gardez votre original hors réseau.</p>

          <h3 style={S.h3}>Générer une clé de Cellule</h3>
          <p style={S.p}>Une clé de Cellule est une clé de chiffrement symétrique de 32 octets. Elle est scellée avec votre clé privée Ed25519 afin que vous seul puissiez l’ouvrir.</p>
          <Code>confidis cellule keygen --private-key &lt;hex&gt; --output ./cellule.key</Code>

          <h3 style={S.h3}>Téléverser un fichier</h3>
          <Code>{`confidis cellule put \\
  --node https://node1.example.com --node https://node2.example.com --node https://node3.example.com \\
  --input ./my-file.pdf \\
  --work-dir ./work \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --public-key <hex-public-key> \\
  --private-key <hex-private-key> \\
  --cellule-key ./cellule.key \\
  --expires-at 2027-01-01T00:00:00Z \\
  --output ./put-result.json`}</Code>

          <p style={S.p}>Le JSON de sortie contient l’identifiant de Cellule, le CID du manifeste, le nombre de shards et les reçus de placement. Le fichier <span style={S.inlineCode}>--registry</span> est mis à jour avec votre nouvel enregistrement de Cellule temporaire.</p>

          <div style={S.warn}>
            <strong>L’expiration est une garantie de confidentialité.</strong> Une fois définie, la date d’expiration ne peut pas être avancée. Elle peut être prolongée avec <span style={S.inlineCode}>cellule renew</span>, mais seulement avant l’expiration, par signature propriétaire, et au maximum pour un an à chaque renouvellement.
          </div>

          <h3 style={S.h3}>Limites d’usage</h3>
          <p style={S.p}>Si le noeud refuse un téléversement, la cause doit être explicite : quota local, durée excessive, fichier trop volumineux, espace disque réservé, peer de fédération non autorisé ou limite de fédération atteinte.</p>
        </section>

        <div style={S.divider} />

        {/* Retrieving */}
        <section id="cellule-get">
          <h2 style={S.h2}><Download size={18} color="var(--accent-primary)" /> Récupérer des données</h2>
          <h3 style={S.h3}>Télécharger et déchiffrer</h3>
          <p style={S.p}>Toute opération qui révèle des données utilisateur, le manifeste complet ou le rapport de placement complet doit être autorisée par la clé du propriétaire. Le noeud peut exposer sa propre santé et les preuves locales de shards, mais il ne peut pas connaître de lui-même tous les emplacements où sont stockés les shards d’une Cellule.</p>
          <Code>{`confidis cellule get \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --private-key <hex> \\
  --cellule-key ./cellule.key \\
  --output ./recovered-file.pdf`}</Code>

          <h3 style={S.h3}>Vérifier la disponibilité des shards</h3>
          <p style={S.p}>Avant de télécharger, vous pouvez vérifier qu’assez de shards sont joignables :</p>
          <Code>{`confidis cellule availability \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --private-key <hex> \\
  --cellule-key ./cellule.key`}</Code>
          <p style={S.p}>CONFIDIS utilise Reed-Solomon 20+10 — 20 shards quelconques parmi 30 suffisent à restaurer vos données.</p>

          <h3 style={S.h3}>Réparer des shards manquants</h3>
          <p style={S.p}>Si des shards manquent (panne de noeud, corruption), la réparation les reconstruit et les re-téléverse :</p>
          <Code>{`confidis cellule repair \\
  --node https://node1.example.com --node https://node2.example.com \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --private-key <hex> \\
  --cellule-key ./cellule.key \\
  --work-dir ./work \\
  --output ./repair-result.json`}</Code>
        </section>

        <div style={S.divider} />

        {/* Sharing */}
        <section id="sharing">
          <h2 style={S.h2}><Share2 size={18} color="var(--accent-primary)" /> Partager l’accès</h2>
          <p style={S.p}>Le parcours de production est le partage par package : vous créez une copie chiffrée pour le destinataire — une organisation ou une personne représentée par une clé publique. Le package est autorisé par votre signature de propriétaire, adressé à la clé de chiffrement du destinataire et limité à des champs ou périmètres sélectionnés.</p>
          <p style={S.p}>Un package destinataire ne contient pas votre clé privée de propriétaire, ne contient pas la clé de Cellule et ne donne au destinataire ni renouvellement, ni suppression, ni wallet, ni rapport, ni autorité de re-partage. Retirer ou faire expirer le package interrompt toute livraison future de cette copie médiée par CONFIDIS.</p>
          <p style={S.p}>Le wallet affiche ces enregistrements comme des copies partagées, avec destinataire, champs, date de création, expiration, preuves de livraison et actions de retrait.</p>
          <Code>{`confidis cellule fields-seal \\
  --cellule-id <id> \\
  --input ./fields.json \\
  --private-key <hex> \\
  --cellule-key ./cellule.key \\
  --output ./fields.container.json

confidis cellule fields-open \\
  --container ./fields.container.json \\
  --private-key <hex> \\
  --cellule-key ./cellule.key \\
  --scope kyc.status \\
  --output ./kyc-status.json`}</Code>
          <p style={S.p}>Les conteneurs de champs chiffrent chaque champ JSON indépendamment par nom de périmètre. Ouvrir <span style={S.inlineCode}>kyc.status</span> ne déchiffre pas des champs non liés tels que <span style={S.inlineCode}>identity.company_name</span>.</p>
          <Code>{`confidis cellule fields-export \\
  --container ./fields.container.json \\
  --private-key <hex> \\
  --cellule-key ./cellule.key \\
  --recipient-x25519-pubkey <company-x25519-public-key> \\
  --scope kyc.status \\
  --output ./company.package.json

confidis cellule fields-recipient-open \\
  --package ./company.package.json \\
  --recipient-x25519-secret <company-x25519-secret> \\
  --output ./company-fields.json`}</Code>
          <p style={S.p}>Un package de champs destinataire ne contient que les champs sélectionnés re-chiffrés vers la clé de chiffrement du destinataire. L’organisation peut ouvrir le package sans recevoir la clé de Cellule, et les noeuds peuvent médier la livraison du package via l’état de l’inventaire des packages, la preuve de possession du destinataire, la signature du package et le périmètre demandé.</p>
          <h3 style={S.h3}>Sauvegarde du propriétaire</h3>
          <p style={S.p}>Votre phrase de récupération de wallet de 24 mots ne sert qu’à votre propre récupération. Ne la donnez pas à une organisation, un opérateur de noeud, un support ou un destinataire. Un destinataire doit recevoir un package chiffré vers sa clé publique, pas votre clé de Cellule ni votre matériel de récupération de wallet.</p>
          <div style={S.warn}>L’export brut de clé de Cellule est un parcours hérité de récupération/test et est désactivé dans les flux de production normaux.</div>
        </section>

        <div style={S.divider} />

        {/* Access Control */}
        <section id="access-control">
          <h2 style={S.h2}><Shield size={18} color="var(--accent-primary)" /> Contrôle d’accès</h2>
          <p style={S.p}>Vous contrôlez l’accès au niveau de la Cellule. Votre clé privée Ed25519 contrôle les dépenses du wallet, les enregistrements de Cellule, le renouvellement, la suppression, les packages destinataire et les rapports authentifiés par le propriétaire. Un package destinataire ne contient qu’une copie chiffrée à périmètre limité pour un destinataire : celui-ci peut lire cette copie mais ne peut pas gérer votre wallet, supprimer vos Cellules, prolonger la conservation ni accéder à d’autres Cellules.</p>

          <h3 style={S.h3}>Parcours de visite en organisation</h3>
          <p style={S.p}>Lorsque vous créez une Cellule chez une organisation, celle-ci fournit le matériel, la connectivité et une identité opérateur à clé publique. Vous restez le propriétaire. Vous pouvez créer un package chiffré pour l’identité à clé publique de l’organisation, tandis que renouvellement, suppression, migration, rapports complets et re-partage restent sous votre clé de propriétaire.</p>

          <h3 style={S.h3}>Qui voit quoi</h3>
          <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 2 }}>
            <li><strong>Navigateur non authentifié :</strong> interface publique uniquement ; aucun rapport de données du propriétaire.</li>
            <li><strong>Noeud local :</strong> sa propre santé, l’état de la liste de quarantaine de l’autorité, la liste des pairs, la capacité, et les shards chiffrés qu’il stocke localement.</li>
            <li><strong>Identité d’organisation / destinataire d’un partage :</strong> accès en lecture seule uniquement aux packages destinataire actifs adressés à sa clé publique.</li>
            <li><strong>Propriétaire après authentification par signature :</strong> rapport complet pour ses Cellules, y compris le placement dérivé du manifeste et les preuves de cycle de vie.</li>
          </ul>

          <h3 style={S.h3}>Modifier l’accès</h3>
          <p style={S.p}>Le propriétaire peut créer, retirer ou faire expirer des packages destinataire à tout moment, idéalement par champ. Le retrait interrompt la livraison future de package médiée par CONFIDIS. Si un destinataire a déjà consulté ou exporté du texte en clair pendant la validité de l’accès, CONFIDIS ne peut pas techniquement récupérer cette copie.</p>

          <h3 style={S.h3}>Preuve de rapport du propriétaire</h3>
          <p style={S.p}>Pour les rapports réservés au propriétaire, l’interface web demande un challenge à durée de vie courte et affiche une commande de signature locale. Exécutez <span style={S.inlineCode}>confidis cellule report-proof</span> dans votre terminal, puis collez uniquement le JSON de preuve signé dans l’interface. Cela autorise le flux de rapport sans mettre de clés privées dans le navigateur.</p>
          <Code>{`confidis cellule report-proof \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --owner-private-key <hex> \\
  --challenge <hex-nonce> \\
  --scope cellule.report \\
  --output ./owner-report-proof.json`}</Code>
          <Code>{`confidis cellule report-export \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --owner-private-key <hex> \\
  --cellule-key ./cellule.key \\
  --proof ./owner-report-proof.json \\
  --output ./owner-report.json`}</Code>
          <p style={S.p}>Le rapport exporté est reconstruit localement à partir de votre manifeste chiffré et peut être importé dans le panneau « Rapport du propriétaire ». Il inclut le placement, le fournisseur, la région, le domaine de panne, les preuves de restauration/réparation et l’état au niveau des shards.</p>

          <h3 style={S.h3}>Comportement recommandé du lecteur</h3>
          <p style={S.p}>Les organisations devraient lire les données déléguées via le client ou l’API CONFIDIS pendant la durée autorisée, plutôt que de transformer un package temporaire en copie locale permanente. Pour des flux CRM ou d’automatisation, intégrez-vous à CONFIDIS et conservez la piste d’audit. Le produit devrait le rappeler à chaque lecteur avant l’accès.</p>
        </section>

        <div style={S.divider} />

        {/* Data Health */}
        <section id="data-health">
          <h2 style={S.h2}><Activity size={18} color="var(--accent-primary)" /> Santé des données</h2>
          <p style={S.p}>La Santé des données est la vue opérationnelle de la résilience pour l’utilisateur. Elle montre la santé des noeuds, l’adéquation du stockage, les preuves locales de shards, les pairs, l’état d’expiration et les reçus signés, sans exposer de clés privées au navigateur.</p>
          <p style={S.p}>Elle montre aussi l’état de maintenance autonome via <span style={S.inlineCode}>GET /maintenance</span> : nettoyage à l’expiration, intégrité des shards, découverte de pairs, rafraîchissement de la liste de quarantaine de l’autorité, gossip de disponibilité et nettoyage des sessions sécurisées. Le noeud persiste cela dans <span style={S.inlineCode}>store/maintenance/status.json</span> afin que les mêmes preuves puissent être exportées avec les événements de sécurité.</p>
          <p style={S.p}>Un noeud local ne prétend pas connaître à lui seul le placement global complet de chaque Cellule. Le rapport complet par Cellule n’est construit qu’après que le propriétaire a signé un challenge d’authentification à durée de vie courte ; le client peut alors utiliser le contexte de manifeste côté propriétaire pour montrer où ses shards sont stockés.</p>
          <p style={S.p}>La même vue montre l’état du noeud via <span style={S.inlineCode}>GET /health</span> : identité locale, stockage, exposition de l’interface, quotas, pairs de fédération et readiness. La préparation à la production est vérifiée par la configuration, les limites d’usage et les preuves d’exploitation.</p>
        </section>

        <div style={S.divider} />

        {/* Renewal */}
        <section id="renew">
          <h2 style={S.h2}><RefreshCw size={18} color="var(--accent-primary)" /> Renouvellement</h2>
          <p style={S.p}>Pour prolonger la durée de vie d’une Cellule avant son expiration, utilisez <span style={S.inlineCode}>cellule renew</span>. Une Cellule peut être prolongée à tout moment par le propriétaire, mais la nouvelle durée de vie doit être au plus d’un an à compter de la date de renouvellement. Le renouvellement re-téléverse tous les shards avec la nouvelle expiration, reconstruit le manifeste et incrémente la séquence de l’enregistrement.</p>
          <Code>{`confidis cellule renew \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --private-key <hex> \\
  --cellule-key ./cellule.key \\
  --expires-at 2028-01-01T00:00:00Z`}</Code>

          <p style={S.p}>Pour trouver les Cellules proches de l’expiration :</p>
          <Code>confidis cellule expiry-check --registry ./registry.json --days 30</Code>

          <div style={S.warn}>
            Le renouvellement n’est possible que pour les Cellules <strong>actives</strong> (non expirées). Une fois une Cellule expirée, elle ne peut pas être renouvelée — vous devez en créer une nouvelle.
          </div>
        </section>

        <div style={S.divider} />

        {/* Deletion */}
        <section id="delete">
          <h2 style={S.h2}><Trash2 size={18} color="var(--accent-primary)" /> Suppression</h2>
          <p style={S.p}>Les Cellules sont supprimées automatiquement à leur horodatage d’expiration. Pour supprimer immédiatement :</p>
          <Code>{`confidis cellule delete \\
  --cellule-id <id> \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --private-key <hex> \\
  --cellule-key ./cellule.key`}</Code>
          <p style={S.p}>Chaque noeud renvoie un reçu de suppression signé. La CLI vérifie les reçus avant de signaler le succès. Les échecs partiels (noeuds temporairement hors ligne) sont sûrs — l’opération peut être réessayée ; les noeuds utilisent des tombstones d’autorisation pour rendre la suppression idempotente.</p>

          <h3 style={S.h3}>Export d’audit de conformité</h3>
          <p style={S.p}>Générer un package complet de preuves de conformité pour toutes les Cellules :</p>
          <Code>{`confidis cellule audit-export \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --private-key <hex> \\
  --cellule-key ./cellule.key`}</Code>
          <p style={S.p}>La sortie inclut l’état du cycle de vie, les métadonnées du manifeste, la disposition des shards et les emplacements des fournisseurs pour chaque Cellule. C’est une preuve à l’appui des registres RGPD ; le registre final au titre de l’article 30 et l’analyse des rôles juridiques doivent être validés par l’organisation ou son DPO.</p>
        </section>

        <div style={S.divider} />

        {/* Security */}
        <section id="security">
          <h2 style={S.h2}><Shield size={18} color="var(--accent-primary)" /> Sécurité des clés</h2>
          <p style={S.p}>Votre clé privée Ed25519 contrôle toutes les opérations de la Cellule réseau. Sa perte rend irréversible l’accès à cette Cellule existante, mais ne détruit pas les originaux que vous conservez hors réseau. Suivez ces pratiques :</p>

          <h3 style={S.h3}>Sauvegardez votre clé privée</h3>
          <p style={S.p}>Conservez le secret hors ligne dans au moins deux emplacements physiquement séparés, par exemple une clé USB chiffrée, un kit d’urgence de gestionnaire de mots de passe, ou une impression papier dans un coffre ignifuge.</p>

          <h3 style={S.h3}>Sauvegardez votre clé de Cellule</h3>
          <p style={S.p}>Le fichier de clé de Cellule (<span style={S.inlineCode}>./cellule.key</span>) est scellé avec votre clé privée. Sauvegardez les deux. Les packages destinataire sont le parcours de partage normal ; l’export brut de clé de Cellule est hérité/réservé au dev et ne doit pas être utilisé comme UX de production normale.</p>

          <h3 style={S.h3}>Ne partagez jamais votre clé privée Ed25519</h3>
          <div style={S.warn}>
            <strong>Ne partagez jamais votre clé privée Ed25519 ni votre phrase de récupération de wallet.</strong> Elle contrôle votre wallet, vos enregistrements de Cellule et l’autorité de suppression. Un destinataire ne doit recevoir qu’un package créé par le propriétaire et adressé à sa clé publique.
          </div>

          <h3 style={S.h3}>Rotation de clé</h3>
          <p style={S.p}>Si vous pensez que votre clé est compromise, créez une nouvelle paire de clés, téléversez vos données vers une nouvelle Cellule sous la nouvelle clé, et laissez l’ancienne Cellule expirer. Il n’y a pas de rotation de clé sur place — par conception, une compromission de clé est contenue aux Cellules qui utilisaient la clé compromise.</p>
        </section>
      </div>
    </div>
  );
}
