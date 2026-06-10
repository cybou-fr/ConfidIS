import { useState } from 'react';
import { Activity, AlertTriangle, Server, Settings, Shield, Terminal } from 'lucide-react';

const S = {
  page: { padding: '2rem', maxWidth: '900px' },
  h1: { fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' },
  h2: { fontSize: '1.35rem', fontWeight: 700, margin: '2.5rem 0 1rem', display: 'flex', alignItems: 'center', gap: '0.6rem' },
  h3: { fontSize: '1.05rem', fontWeight: 600, margin: '1.5rem 0 0.5rem', color: 'var(--accent-primary)' },
  p: { color: 'var(--text-secondary)', lineHeight: 1.75, marginBottom: '0.75rem', fontSize: '0.925rem' },
  code: {
    display: 'block', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border-color)',
    borderRadius: '10px', padding: '1rem 1.25rem', fontFamily: 'monospace',
    fontSize: '0.825rem', color: '#a5f3fc', marginBottom: '1rem', overflowX: 'auto', lineHeight: 1.6,
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
        {copied ? 'copié' : 'copier'}
      </button>
    </div>
  );
}

const sections = [
  { id: 'overview', icon: <Server size={20} />, label: 'Vue d’ensemble' },
  { id: 'install', icon: <Terminal size={20} />, label: 'Installation' },
  { id: 'config', icon: <Settings size={20} />, label: 'Configuration' },
  { id: 'federation', icon: <Shield size={20} />, label: 'Fédération' },
  { id: 'monitoring', icon: <Activity size={20} />, label: 'Supervision' },
  { id: 'ops', icon: <AlertTriangle size={20} />, label: 'Exploitation' },
];

export default function DocsAdmin() {
  const [active, setActive] = useState('overview');
  const scrollTo = (id) => { setActive(id); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); };

  return (
    <div style={{ display: 'flex', gap: '2rem', padding: '2rem' }}>
      <aside style={{ width: '200px', flexShrink: 0, position: 'sticky', top: '2rem', alignSelf: 'flex-start' }}>
        <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.75rem', fontWeight: 600 }}>Sur cette page</p>
        {sections.map(s => (
          <button key={s.id} onClick={() => scrollTo(s.id)}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', width: '100%', background: 'transparent', border: 'none', padding: '0.4rem 0.5rem', borderRadius: '6px', color: active === s.id ? 'var(--accent-primary)' : 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.8rem', textAlign: 'left', marginBottom: '0.1rem' }}>
            {s.icon}{s.label}
          </button>
        ))}
      </aside>

      <div style={{ flex: 1, maxWidth: '700px' }}>
        <header style={{ marginBottom: '2.5rem' }}>
          <h1 style={S.h1}><Server color="var(--accent-primary)" /> Documentation administrateur</h1>
          <p style={S.p}>CONFIDIS OS est une appliance self-hosted pour Cellules temporaires chiffrées. L’exploitation repose sur quotas locaux, signatures propriétaire, preuves d’usage et fédération explicite entre noeuds de confiance.</p>
        </header>

        <section id="overview">
          <h2 style={S.h2}><Server size={18} color="var(--accent-primary)" /> Vue d’ensemble</h2>
          <p style={S.p}>Un noeud CONFIDIS stocke des shards Reed-Solomon chiffrés, signe des reçus, rapporte sa capacité, applique l’expiration et participe à la découverte de pairs configurés. Il ne stocke ni texte en clair, ni clé de Cellule, ni secret propriétaire.</p>
          <p style={S.p}>CONFIDIS OS v1 ne demande pas de token CYB, de solde, de top-up, de ledger économique ou de signer d’autorité pour accepter une Cellule. L’admission normale est contrôlée par les limites de durée, de capacité, de nombre de shards et de nombre de Cellules par propriétaire.</p>
          <div style={S.note}>Spécification de départ recommandée : 2 vCPU, 4 Go RAM et SSD supérieur au quota configuré. Pour un pilote, 500 Go utiles donnent une marge confortable.</div>
        </section>

        <div style={S.divider} />

        <section id="install">
          <h2 style={S.h2}><Terminal size={18} color="var(--accent-primary)" /> Installation</h2>
          <h3 style={S.h3}>Depuis les sources</h3>
          <Code>{`git clone https://github.com/confidis-project/confidis
cd confidis
cargo build --release`}</Code>

          <h3 style={S.h3}>Déploiement accompagné ou serveur Debian</h3>
          <Code>sudo bash deploy/deploy.sh --domain confidis.example --email admin@example.org</Code>
          <p style={S.p}>Le script prépare le service local, l’interface web, Nginx/TLS et une configuration de production sans dépendance ledger. Le noeud applicatif reste lié à <span style={S.inlineCode}>127.0.0.1:4433</span> ; le trafic public passe par HTTPS sur 443.</p>

          <h3 style={S.h3}>Configuration manuelle</h3>
          <Code>{`confidis node init-config \\
  --node-id node-paris-01 \\
  --production-profile \\
  --transport-policy https_reverse_proxy \\
  --listen-addr 127.0.0.1:4433 \\
  --public-endpoint https://confidis.example \\
  --store-path /var/lib/confidis/shards \\
  --region eu-fr \\
  --failure-domain paris-dc1 \\
  --max-bytes 53687091200 \\
  --ui-allowed-origin https://confidis.example \\
  --max-shards-per-owner-per-hour 1000 \\
  --max-cellules-per-owner 100 \\
  --packages-path /var/lib/confidis/packages.json \\
  --webui-path /usr/share/confidis/web-ui \\
  --content-dir /usr/share/confidis/content \\
  --peer https://trusted-peer.example \\
  /etc/confidis/node.json`}</Code>
          <p style={S.p}>Si les clés locales du noeud sont absentes, le daemon les crée au premier démarrage dans son répertoire d’identité protégé.</p>
        </section>

        <div style={S.divider} />

        <section id="config">
          <h2 style={S.h2}><Settings size={18} color="var(--accent-primary)" /> Configuration</h2>
          <p style={S.p}>Les champs importants pour CONFIDIS OS v1 :</p>
          <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '1rem 1.25rem', marginBottom: '1rem', fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            {[
              ['node_id', 'Identifiant lisible du noeud'],
              ['listen_addr', 'Socket local, généralement 127.0.0.1:4433'],
              ['public_endpoint', 'URL HTTPS annoncée aux pairs'],
              ['bootstrap_peers', 'Pairs de fédération de confiance (champ technique legacy)'],
              ['store_path', 'Répertoire des shards chiffrés'],
              ['registry_path', 'Registre local des Cellules'],
              ['packages_path', 'Inventaire des packages destinataire'],
              ['max_bytes', 'Quota disque maximal du noeud'],
              ['max_shards_per_owner_per_hour', 'Limite anti-abus par propriétaire'],
              ['max_cellules_per_owner', 'Limite de Cellules par propriétaire'],
              ['ui_allowed_origin', 'Origine navigateur autorisée'],
              ['webui_path', 'Bundle UI servi par le noeud'],
              ['content_dir', 'Pages publiques locales'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: '1rem', paddingBottom: '0.3rem', borderBottom: '1px solid rgba(255,255,255,0.04)', marginBottom: '0.3rem' }}>
                <span style={{ fontFamily: 'monospace', color: 'var(--accent-primary)', minWidth: '200px' }}>{k}</span>
                <span>{v}</span>
              </div>
            ))}
          </div>
          <p style={S.p}>Les champs legacy <span style={S.inlineCode}>ledger_path</span>, <span style={S.inlineCode}>authority_spend_url</span>, <span style={S.inlineCode}>payer_mode</span> et <span style={S.inlineCode}>confidis_root_pubkey</span> peuvent encore être lus par compatibilité, mais ils ne sont pas requis pour le profil production CONFIDIS OS v1.</p>
        </section>

        <div style={S.divider} />

        <section id="federation">
          <h2 style={S.h2}><Shield size={18} color="var(--accent-primary)" /> Fédération</h2>
          <p style={S.p}>La fédération est un ensemble de noeuds choisis, pas une DHT publique ouverte. L’opérateur configure les pairs de confiance, les domaines de panne, les régions et les limites de placement. Chaque noeud garde sa propre politique de quota.</p>
          <p style={S.p}>Pour un pilote, utilisez au moins trois endpoints HTTPS : noeud principal, noeud partenaire/réserve et deuxième noeud partenaire ou de test. Les records de pair et de capacité sont signés par les identités de noeud.</p>
        </section>

        <div style={S.divider} />

        <section id="monitoring">
          <h2 style={S.h2}><Activity size={18} color="var(--accent-primary)" /> Supervision</h2>
          <h3 style={S.h3}>Santé</h3>
          <Code>curl http://127.0.0.1:4433/health</Code>
          <p style={S.p}>La santé expose la disponibilité locale, la posture UI, l’état de la surface publique et les informations de quarantaine si elles sont configurées.</p>
          <h3 style={S.h3}>Capacité</h3>
          <Code>confidis remote capacity --node http://127.0.0.1:4433</Code>
          <p style={S.p}>Le rapport de capacité inclut les octets utilisés, le nombre de shards, la région, le domaine de panne et un score de santé signé.</p>
          <h3 style={S.h3}>Preuves</h3>
          <p style={S.p}>Les reçus de stockage, lecture et suppression forment la preuve d’exploitation. Les rapports complets par Cellule exigent une authentification propriétaire par signature.</p>
        </section>

        <div style={S.divider} />

        <section id="ops">
          <h2 style={S.h2}><AlertTriangle size={18} color="var(--accent-secondary)" /> Exploitation</h2>
          <h3 style={S.h3}>Sauvegardes</h3>
          <p style={S.p}>Sauvegardez <span style={S.inlineCode}>/etc/confidis</span>, l’identité locale du noeud, les registres, les packages et les reçus. Les shards chiffrés suivent la politique de rétention de l’organisation.</p>
          <h3 style={S.h3}>Surface publique</h3>
          <p style={S.p}>Bloquez les routes de gestion sur Internet : <span style={S.inlineCode}>/operator</span>, <span style={S.inlineCode}>/maintenance</span>, <span style={S.inlineCode}>/metrics</span> et <span style={S.inlineCode}>/receipts</span>.</p>
        </section>
      </div>
    </div>
  );
}
section>
      </div>
    </div>
  );
}
