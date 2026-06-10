import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  Link as LinkIcon,
  RefreshCw,
  Server,
  Settings,
  Shield,
  XCircle,
} from 'lucide-react';
import { fetchCapacity, fetchHealth, fetchPeers, formatBytes, nodeBaseUrl, uiTokenConfigured } from '../api';

const cardStyle = {
  padding: '1rem',
  border: '1px solid var(--border-color)',
  borderRadius: 8,
  background: 'rgba(255,255,255,0.025)',
};

const codeStyle = {
  fontFamily: 'monospace',
  background: 'rgba(255,255,255,0.07)',
  padding: '0.12rem 0.38rem',
  borderRadius: 4,
  fontSize: '0.8rem',
};

function StatusBadge({ tone = 'warn', children }) {
  const colors = {
    ok: ['rgba(74,222,128,0.1)', '#4ade80', 'rgba(74,222,128,0.25)'],
    warn: ['rgba(251,146,60,0.1)', '#fb923c', 'rgba(251,146,60,0.25)'],
    risk: ['rgba(255,42,122,0.1)', 'var(--accent-secondary)', 'rgba(255,42,122,0.25)'],
  };
  const [bg, fg, border] = colors[tone] || colors.warn;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.28rem 0.65rem', borderRadius: 999, background: bg, color: fg, border: `1px solid ${border}`, fontSize: '0.75rem', fontWeight: 700 }}>
      {children}
    </span>
  );
}

function ReadinessItem({ label, ok, warn, detail }) {
  const tone = ok ? 'ok' : warn ? 'warn' : 'risk';
  const Icon = ok ? CheckCircle2 : warn ? AlertTriangle : XCircle;
  return (
    <div style={cardStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.75rem', marginBottom: '0.45rem' }}>
        <p style={{ fontWeight: 800, fontSize: '0.9rem' }}>{label}</p>
        <StatusBadge tone={tone}><Icon size={13} />{ok ? 'Prêt' : warn ? 'À revoir' : 'Manquant'}</StatusBadge>
      </div>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', lineHeight: 1.5 }}>{detail}</p>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(130px, 0.7fr) minmax(0, 1.3fr)', gap: '0.8rem', padding: '0.75rem 0', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
      <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>{label}</span>
      <span style={{ fontFamily: 'monospace', fontSize: '0.82rem', overflowWrap: 'anywhere' }}>{value ?? '-'}</span>
    </div>
  );
}

function settingsFromHealth(health, capacity, peers) {
  const peerCount = peers?.peers?.length ?? 0;
  return [
    {
      label: 'Jeton d’API locale',
      ok: Boolean(health?.ui_auth_required),
      detail: health?.ui_auth_required
        ? 'Les routes destinées à l’UI exigent un jeton Bearer.'
        : 'Définissez ui_token avant tout flux opérateur réel ou de données personnelles.',
    },
    {
      label: 'Verrou d’origine navigateur',
      ok: Boolean(health?.ui_cors_restricted),
      warn: Boolean(health?.ui_auth_required && !health?.ui_cors_restricted),
      detail: health?.ui_cors_restricted
        ? 'Le CORS est restreint à l’origine d’interface web configurée.'
        : 'Définissez ui_allowed_origin avant d’exposer le noeud hors de localhost.',
    },
    {
      label: 'Vérification de quarantaine de l’autorité',
      ok: Boolean(health?.ban_verification_enabled && health?.node_ban_list_present && !health?.node_banned),
      warn: Boolean(health?.ban_verification_enabled && !health?.node_banned),
      detail: health?.node_banned
        ? 'Cette clé de noeud figure sur la liste de quarantaine de l’autorité.'
        : health?.ban_verification_enabled
          ? 'La racine de confiance est configurée ; chargez une liste de quarantaine signée valide pour la production.'
          : 'Configurez confidis_root_pubkey et node_ban_list_path pour la préparation à la production.',
    },
    {
      label: 'Découverte de pairs',
      ok: peerCount > 1,
      warn: peerCount === 1,
      detail: peerCount > 1
        ? `${peerCount} pairs sont visibles depuis ce noeud.`
        : 'Ce noeud semble isolé ou ne se voit que lui-même. Configurez des pairs de fédération de confiance pour un vrai réseau.',
    },
    {
      label: 'Allocation de stockage',
      ok: (capacity?.max_bytes || 0) >= 100 * 1024 ** 3,
      warn: Boolean(capacity?.max_bytes),
      detail: capacity
        ? `${formatBytes(capacity.max_bytes)} configurés ; ${formatBytes(capacity.free_bytes || 0)} libres.`
        : 'L’endpoint de capacité n’est pas encore disponible.',
    },
  ];
}

export default function SettingsManager() {
  const [health, setHealth] = useState(null);
  const [capacity, setCapacity] = useState(null);
  const [peers, setPeers] = useState(null);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  async function refresh() {
    setError(null);
    try {
      const [nodeHealth, cap, peerList] = await Promise.all([fetchHealth(), fetchCapacity(), fetchPeers()]);
      setHealth(nodeHealth);
      setCapacity(cap);
      setPeers(peerList);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message || String(err));
    }
  }

  useEffect(() => { refresh(); }, []);

  const readiness = useMemo(() => settingsFromHealth(health, capacity, peers), [health, capacity, peers]);
  const readyCount = readiness.filter((item) => item.ok).length;

  return (
    <div style={{ padding: '2rem' }}>
      <header style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Settings color="var(--text-secondary)" /> Paramètres du noeud
          </h1>
          <p style={{ color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            Vue en lecture seule du périmètre du noeud local et des contrôles de préparation à la production.
          </p>
        </div>
        <button onClick={refresh} className="btn btn-secondary" style={{ padding: '0.55rem 0.85rem' }}>
          <RefreshCw size={15} /> Rafraîchir
        </button>
      </header>

      {error && (
        <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', padding: '0.9rem 1rem', borderRadius: 8, background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.22)', color: 'var(--accent-secondary)', marginBottom: '1rem', fontSize: '0.86rem' }}>
          <AlertTriangle size={16} /> Impossible de lire les paramètres du noeud : {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.1fr) minmax(320px, 0.9fr)', gap: '1rem', alignItems: 'start' }}>
        <section className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={18} color="var(--accent-primary)" /> Préparation à la sécurité
            </h2>
            <StatusBadge tone={readyCount === readiness.length ? 'ok' : 'warn'}>{readyCount}/{readiness.length} prêts</StatusBadge>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: '0.75rem' }}>
            {readiness.map((item) => <ReadinessItem key={item.label} {...item} />)}
          </div>
        </section>

        <section className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Server size={18} color="var(--accent-primary)" /> Noeud courant
          </h2>
          <InfoRow label="API locale" value={nodeBaseUrl()} />
          <InfoRow label="Jeton UI dans le build" value={uiTokenConfigured() ? 'Configuré' : 'Non configuré'} />
          <InfoRow label="ID de noeud" value={capacity?.node_id?.['0'] ?? capacity?.node_id ?? '-'} />
          <InfoRow label="Région" value={capacity?.region ?? '-'} />
          <InfoRow label="Racine de confiance" value={health?.trust_root_source ?? '-'} />
          <InfoRow label="Interface web activée" value={health ? String(Boolean(health.webui_enabled)) : '-'} />
          <InfoRow label="Dernier rafraîchissement" value={lastUpdated ? lastUpdated.toLocaleTimeString() : '-'} />
        </section>
      </div>

      <section className="glass-panel" style={{ padding: '1.5rem', marginTop: '1rem' }}>
        <h2 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <LinkIcon size={18} color="var(--accent-primary)" /> Check-list de config production
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.8rem' }}>
          <div style={cardStyle}>
            <p style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontWeight: 800, marginBottom: '0.5rem' }}><Shield size={15} /> Périmètre navigateur/API</p>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: 1.55 }}>
              Définissez <span style={codeStyle}>ui_token</span>, <span style={codeStyle}>ui_allowed_origin</span>, et servez via HTTPS avant toute exposition publique.
            </p>
          </div>
          <div style={cardStyle}>
            <p style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontWeight: 800, marginBottom: '0.5rem' }}><Server size={15} /> Identité réseau</p>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: 1.55 }}>
              Configurez <span style={codeStyle}>public_endpoint</span>, des pairs de fédération de confiance et des clés de noeud stables.
            </p>
          </div>
          <div style={cardStyle}>
            <p style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontWeight: 800, marginBottom: '0.5rem' }}><HardDrive size={15} /> Stockage et économie</p>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: 1.55 }}>
              Définissez des chemins de store durables, des quotas, une origine UI et des pairs de confiance.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
